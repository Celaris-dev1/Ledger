package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config configures an Authenticator.
type Config struct {
	// Open disables authentication entirely (every request is an anonymous admin). This is the
	// behaviour of an unconfigured ledgerd (no LEDGER_TOKEN, no SSO, no tokens) and is meant
	// for local development only.
	Open bool
	// LegacyToken is the pre-RBAC shared LEDGER_TOKEN; it authenticates as LegacyRole.
	LegacyToken string
	LegacyRole  string // default writer
	OIDC        *OIDCConfig
	SessionTTL  time.Duration // default 12h
	// SecureCookies forces the Secure attribute (it is also set whenever the request came over TLS).
	SecureCookies bool
	HTTPClient    *http.Client // for OIDC discovery/token calls (tests inject the fake issuer's client)
	Now           func() time.Time
	Logger        *log.Logger
}

// Authenticator resolves principals and enforces permissions.
type Authenticator struct {
	Cfg   Config
	Store Store
	oidc  *oidcProvider
	// Denied renders a UI error page (optional); API routes always get JSON.
	Denied func(w http.ResponseWriter, r *http.Request, status int, msg string)
}

// New builds an Authenticator.
func New(cfg Config, st Store) *Authenticator {
	if cfg.LegacyRole == "" {
		cfg.LegacyRole = RoleWriter
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	a := &Authenticator{Cfg: cfg, Store: st}
	if cfg.OIDC != nil && cfg.OIDC.Issuer != "" {
		a.oidc = &oidcProvider{cfg: *cfg.OIDC, client: cfg.HTTPClient}
	}
	return a
}

// SSOEnabled reports whether OIDC login is configured.
func (a *Authenticator) SSOEnabled() bool { return a.oidc != nil }

// SessionCookie is the browser session cookie name.
const SessionCookie = "ledger_session"

// CSRFHeader carries the CSRF token on unsafe cookie-authenticated requests made by scripts.
const CSRFHeader = "X-CSRF-Token"

// CSRFField is the form field carrying the CSRF token.
const CSRFField = "csrf_token"

var errBadToken = errors.New("invalid or revoked bearer token")

// Authenticate resolves the principal of r (nil, nil when there are no credentials).
func (a *Authenticator) Authenticate(r *http.Request) (*Principal, error) {
	ctx := r.Context()
	if h := r.Header.Get("Authorization"); h != "" {
		tok, ok := strings.CutPrefix(h, "Bearer ")
		if !ok {
			if a.Cfg.Open {
				return a.anon(), nil
			}
			return nil, errBadToken
		}
		p, err := a.bearer(ctx, strings.TrimSpace(tok))
		if err != nil || p == nil {
			if a.Cfg.Open && err == nil {
				return a.anon(), nil
			}
			if err == nil {
				err = errBadToken
			}
			return nil, err
		}
		return p, nil
	}
	if c, err := r.Cookie(SessionCookie); err == nil && c.Value != "" {
		p, err := a.session(ctx, c.Value)
		if err != nil {
			return nil, err
		}
		if p != nil {
			return p, nil
		}
	}
	if a.Cfg.Open {
		return a.anon(), nil
	}
	return nil, nil
}

func (a *Authenticator) anon() *Principal {
	return &Principal{Kind: "anonymous", ID: "anonymous", Name: "anonymous (open mode)", Role: RoleAdmin}
}

func (a *Authenticator) bearer(ctx context.Context, tok string) (*Principal, error) {
	if tok == "" {
		return nil, nil
	}
	if a.Cfg.LegacyToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(a.Cfg.LegacyToken)) == 1 {
		return &Principal{Kind: "legacy", ID: "LEDGER_TOKEN", Name: "LEDGER_TOKEN", Role: a.Cfg.LegacyRole}, nil
	}
	if a.Store == nil || !strings.HasPrefix(tok, TokenPrefix) {
		return nil, nil
	}
	t, err := a.Store.TokenByHash(ctx, HashSecret(tok))
	if err != nil || t == nil || t.RevokedAt != nil {
		return nil, err
	}
	now := a.Cfg.Now().UTC()
	if t.LastUsed == nil || now.Sub(*t.LastUsed) > time.Minute {
		_ = a.Store.TouchToken(ctx, t.ID, now)
	}
	return &Principal{Kind: "token", ID: t.ID, Name: t.Name, Role: t.Role}, nil
}

func (a *Authenticator) session(ctx context.Context, raw string) (*Principal, error) {
	if a.Store == nil {
		return nil, nil
	}
	s, err := a.Store.SessionByHash(ctx, HashSecret(raw))
	if err != nil || s == nil {
		return nil, err
	}
	if !a.Cfg.Now().Before(s.ExpiresAt) {
		_ = a.Store.DeleteSession(ctx, s.Hash)
		return nil, nil
	}
	switch s.Kind {
	case "user":
		u, err := a.Store.UserByID(ctx, s.SubjectID)
		if errors.Is(err, ErrNotFound) || (err == nil && u.Disabled) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return &Principal{Kind: "user", ID: u.ID, Name: u.Name, Email: u.Email, Role: u.Role, Session: s}, nil
	case "token":
		t, err := a.Store.TokenByID(ctx, s.SubjectID)
		if errors.Is(err, ErrNotFound) || (err == nil && t.RevokedAt != nil) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return &Principal{Kind: "token", ID: t.ID, Name: t.Name, Role: t.Role, Session: s}, nil
	}
	return nil, nil
}

// StartSession creates a session for (kind, subject) and sets the cookie.
func (a *Authenticator) StartSession(w http.ResponseWriter, r *http.Request, kind, subject string) error {
	raw := RandToken(32)
	now := a.Cfg.Now().UTC()
	s := Session{Hash: HashSecret(raw), Kind: kind, SubjectID: subject, CSRF: RandToken(24), CreatedAt: now, ExpiresAt: now.Add(a.Cfg.SessionTTL)}
	if err := a.Store.InsertSession(r.Context(), s); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: raw, Path: "/", HttpOnly: true, Secure: a.secure(r),
		SameSite: http.SameSiteLaxMode, Expires: s.ExpiresAt})
	return nil
}

func (a *Authenticator) secure(r *http.Request) bool { return a.Cfg.SecureCookies || r.TLS != nil }

// sameOrigin rejects cross-site unsafe requests: an Origin (or, failing that, Referer)
// header that is present must name this host.
func sameOrigin(r *http.Request) bool {
	check := func(v string) bool {
		u, err := url.Parse(v)
		return err == nil && u.Host != "" && strings.EqualFold(u.Host, r.Host)
	}
	if o := r.Header.Get("Origin"); o != "" {
		return o != "null" && check(o)
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return check(ref)
	}
	return true
}

func unsafeMethod(m string) bool {
	return m != http.MethodGet && m != http.MethodHead && m != http.MethodOptions
}

// CheckCSRF validates a cookie-authenticated unsafe request.
func CheckCSRF(r *http.Request, s *Session) bool {
	if s == nil || !unsafeMethod(r.Method) {
		return true
	}
	if !sameOrigin(r) {
		return false
	}
	got := r.Header.Get(CSRFHeader)
	if got == "" {
		ct := r.Header.Get("Content-Type")
		if strings.HasPrefix(ct, "application/x-www-form-urlencoded") || strings.HasPrefix(ct, "multipart/form-data") {
			got = r.PostFormValue(CSRFField)
		}
	}
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(s.CSRF)) == 1
}

// Require wraps next: the caller must hold perm. api selects JSON errors (and 401 instead of
// a login redirect).
func (a *Authenticator) Require(perm Perm, api bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := a.Authenticate(r)
		if err != nil && !errors.Is(err, errBadToken) {
			a.Cfg.Logger.Printf("ledgerd: auth: %v", err)
			a.deny(w, r, api, http.StatusInternalServerError, "authentication backend error")
			return
		}
		if p == nil {
			if !api && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
				http.Redirect(w, r, "/login?next="+url.QueryEscape(SafeNext(r.URL.RequestURI())), http.StatusSeeOther)
				return
			}
			msg := "missing or invalid bearer token"
			if !api {
				msg = "sign in required"
			}
			a.deny(w, r, api, http.StatusUnauthorized, msg)
			return
		}
		if !p.Can(perm) {
			a.deny(w, r, api, http.StatusForbidden, "role "+p.Role+" may not "+string(perm))
			return
		}
		if !CheckCSRF(r, p.Session) {
			a.deny(w, r, api, http.StatusForbidden, "CSRF check failed")
			return
		}
		next(w, r.WithContext(WithPrincipal(r.Context(), p)))
	}
}

// Optional attaches the principal (if any) without requiring one.
func (a *Authenticator) Optional(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if p, err := a.Authenticate(r); err == nil && p != nil {
			r = r.WithContext(WithPrincipal(r.Context(), p))
		}
		next(w, r)
	}
}

func (a *Authenticator) deny(w http.ResponseWriter, r *http.Request, api bool, code int, msg string) {
	if !api && a.Denied != nil {
		a.Denied(w, r, code, msg)
		return
	}
	if code == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="ledger"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// SafeNext only allows local absolute paths. Browsers strip tab/CR/LF from URLs and treat
// "\\" like "/", so "/\t/evil.com" or "/\\evil.com" could otherwise leave the site.
func SafeNext(n string) string {
	if !strings.HasPrefix(n, "/") || strings.HasPrefix(n, "//") || strings.ContainsAny(n, "\\") {
		return "/"
	}
	for _, r := range n {
		if r < 0x20 || r == 0x7f {
			return "/"
		}
	}
	u, err := url.Parse(n)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || strings.HasPrefix(u.Path, "//") {
		return "/"
	}
	if strings.HasPrefix(u.Path, "/auth/") {
		return "/"
	}
	return n
}

func loginFail(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/login?error="+url.QueryEscape(msg), http.StatusSeeOther)
}

// LoginCSRFCookie protects the pre-session login form (double-submit cookie).
const LoginCSRFCookie = "ledger_login_csrf"

// LoginCSRF returns the login-form CSRF value, setting the cookie when absent.
func (a *Authenticator) LoginCSRF(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(LoginCSRFCookie); err == nil && len(c.Value) >= 20 {
		return c.Value
	}
	v := RandToken(24)
	http.SetCookie(w, &http.Cookie{Name: LoginCSRFCookie, Value: v, Path: "/", HttpOnly: true, Secure: a.secure(r), SameSite: http.SameSiteStrictMode, MaxAge: 3600})
	return v
}

// HandleTokenLogin (POST /auth/token) starts a browser session from an API token of a role
// that may view the UI (writer tokens are for agents and cannot sign in).
func (a *Authenticator) HandleTokenLogin(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(LoginCSRFCookie)
	if err != nil || !sameOrigin(r) || subtle.ConstantTimeCompare([]byte(r.PostFormValue(CSRFField)), []byte(c.Value)) != 1 {
		loginFail(w, r, "login form expired; try again")
		return
	}
	next := SafeNext(r.PostFormValue("next"))
	tok := strings.TrimSpace(r.PostFormValue("token"))
	if a.Store == nil || !strings.HasPrefix(tok, TokenPrefix) {
		loginFail(w, r, "invalid token")
		return
	}
	t, err := a.Store.TokenByHash(r.Context(), HashSecret(tok))
	if err != nil || t == nil || t.RevokedAt != nil {
		loginFail(w, r, "invalid token")
		return
	}
	if !Can(t.Role, PermView) {
		loginFail(w, r, "a "+t.Role+" token cannot sign in to the UI")
		return
	}
	if err := a.StartSession(w, r, "token", t.ID); err != nil {
		a.Cfg.Logger.Printf("ledgerd: session: %v", err)
		loginFail(w, r, "could not start session")
		return
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// HandleLogout (POST /auth/logout; CSRF-checked by Require) ends the session.
func (a *Authenticator) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if p := FromContext(r.Context()); p != nil && p.Session != nil {
		_ = a.Store.DeleteSession(r.Context(), p.Session.Hash)
	}
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.secure(r), SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
