package web

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/auth"
)

// EnvConfig is the UI/auth configuration read from the environment by ledgerd.
type EnvConfig struct {
	UIEnabled  bool          // LEDGER_UI != off
	AuthMode   string        // LEDGER_AUTH: "" (auto) | on | off
	Auth       auth.Config   // LEDGER_TOKEN, LEDGER_TOKEN_ROLE, LEDGER_OIDC_*, LEDGER_SESSION_TTL, LEDGER_SECURE_COOKIES
	StreamPoll time.Duration // LEDGER_STREAM_POLL (default 2s)
	// Tenancy is set when LEDGER_TOKENS configures multi-tenancy. Open mode is then refused:
	// tenant tokens only authenticate the tenant-scoped API routes, so an open UI and
	// /v1/stream would hand every tenant's records (and /admin) to anonymous callers.
	Tenancy  bool
	Warnings []string
}

func csv(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ConfigFromEnv parses the UI/auth environment variables.
func ConfigFromEnv(getenv func(string) string) (EnvConfig, error) {
	c := EnvConfig{UIEnabled: getenv("LEDGER_UI") != "off", AuthMode: strings.ToLower(getenv("LEDGER_AUTH")), StreamPoll: 2 * time.Second,
		Tenancy: strings.TrimSpace(getenv("LEDGER_TOKENS")) != ""}
	switch c.AuthMode {
	case "", "auto", "on", "off":
	default:
		return c, fmt.Errorf("LEDGER_AUTH must be on, off or empty (auto)")
	}
	c.Auth.LegacyToken = getenv("LEDGER_TOKEN")
	c.Auth.LegacyRole = auth.RoleWriter
	if r := getenv("LEDGER_TOKEN_ROLE"); r != "" {
		if !auth.ValidRole(r) {
			return c, fmt.Errorf("LEDGER_TOKEN_ROLE: unknown role %q", r)
		}
		c.Auth.LegacyRole = r
		if r != auth.RoleWriter {
			c.Warnings = append(c.Warnings, "LEDGER_TOKEN_ROLE="+r+": the shared legacy token has more than append rights; prefer per-client tokens (ledger token create)")
		}
	}
	if v := getenv("LEDGER_SESSION_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Minute {
			return c, fmt.Errorf("LEDGER_SESSION_TTL: want a duration >= 1m")
		}
		c.Auth.SessionTTL = d
	}
	c.Auth.SecureCookies = getenv("LEDGER_SECURE_COOKIES") == "1" || getenv("LEDGER_SECURE_COOKIES") == "true" ||
		strings.HasPrefix(getenv("LEDGER_OIDC_REDIRECT_URL"), "https://")
	if v := getenv("LEDGER_STREAM_POLL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 100*time.Millisecond {
			return c, fmt.Errorf("LEDGER_STREAM_POLL: want a duration >= 100ms")
		}
		c.StreamPoll = d
	}
	if iss := getenv("LEDGER_OIDC_ISSUER"); iss != "" {
		o := &auth.OIDCConfig{
			Issuer: iss, ClientID: getenv("LEDGER_OIDC_CLIENT_ID"), ClientSecret: getenv("LEDGER_OIDC_CLIENT_SECRET"),
			RedirectURL: getenv("LEDGER_OIDC_REDIRECT_URL"), Scopes: csv(getenv("LEDGER_OIDC_SCOPES")),
			DefaultRole: getenv("LEDGER_OIDC_DEFAULT_ROLE"), AdminEmails: csv(getenv("LEDGER_OIDC_ADMIN_EMAILS")),
			AuditorEmails: csv(getenv("LEDGER_OIDC_AUDITOR_EMAILS")), AllowDomains: csv(getenv("LEDGER_OIDC_ALLOW_DOMAINS")),
			TrustUnverifiedEmail: getenv("LEDGER_OIDC_TRUST_UNVERIFIED_EMAIL") == "1",
		}
		if s := getenv("LEDGER_SESSION_SECRET"); s != "" {
			o.CookieSecret = []byte(s)
		}
		if o.ClientID == "" || o.RedirectURL == "" {
			return c, fmt.Errorf("LEDGER_OIDC_ISSUER needs LEDGER_OIDC_CLIENT_ID and LEDGER_OIDC_REDIRECT_URL")
		}
		switch o.DefaultRole {
		case "", auth.RoleViewer, auth.RoleAuditor, auth.RoleAdmin:
		default:
			return c, fmt.Errorf("LEDGER_OIDC_DEFAULT_ROLE must be viewer, auditor or admin")
		}
		if o.TrustUnverifiedEmail {
			c.Warnings = append(c.Warnings, "LEDGER_OIDC_TRUST_UNVERIFIED_EMAIL=1: emails the IdP did not verify can match admin/auditor lists")
		}
		c.Auth.OIDC = o
	}
	return c, nil
}

// ResolveOpen decides whether authentication is off. Auto mode is open only when nothing is
// configured at all: no LEDGER_TOKEN, no SSO and no active API tokens (so upgrading an
// existing unauthenticated deployment changes nothing until an operator adds credentials).
func (c *EnvConfig) ResolveOpen(ctx context.Context, st auth.Store) (bool, error) {
	switch c.AuthMode {
	case "off":
		if c.Tenancy {
			return false, fmt.Errorf("LEDGER_AUTH=off cannot be combined with LEDGER_TOKENS (multi-tenancy): open mode would expose every tenant through the UI and /v1/stream")
		}
		return true, nil
	case "on":
		return false, nil
	}
	if c.Tenancy {
		return false, nil
	}
	if c.Auth.LegacyToken != "" || c.Auth.OIDC != nil {
		return false, nil
	}
	if st == nil {
		return true, nil
	}
	n, err := st.CountActiveTokens(ctx)
	if err != nil {
		return false, err
	}
	return n == 0, nil
}
