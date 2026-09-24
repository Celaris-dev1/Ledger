package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCConfig configures single sign-on (authorization code flow with PKCE).
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string // absolute, e.g. https://ledger.example.com/auth/callback
	Scopes       []string
	// DefaultRole for users not listed below (viewer when empty). Writer is not allowed.
	DefaultRole   string
	AdminEmails   []string
	AuditorEmails []string
	// AllowDomains restricts sign-in to these email domains (empty = any).
	AllowDomains []string
	// TrustUnverifiedEmail treats emails without email_verified=true as verified. Off by
	// default: role grants and domain checks only honour emails the IdP vouches for.
	TrustUnverifiedEmail bool
	// CookieSecret signs the short-lived login-state cookie (random per process when empty).
	CookieSecret []byte
}

type oidcProvider struct {
	cfg    OIDCConfig
	client *http.Client

	mu       sync.Mutex
	secret   []byte
	provider *oidc.Provider
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func (o *oidcProvider) ctx(ctx context.Context) context.Context {
	if o.client != nil {
		return oidc.ClientContext(ctx, o.client)
	}
	return ctx
}

// init performs discovery once (retried on failure, so a down IdP at boot is not fatal).
func (o *oidcProvider) init(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.provider != nil {
		return nil
	}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(o.ctx(dctx), o.cfg.Issuer)
	if err != nil {
		return fmt.Errorf("oidc discovery: %w", err)
	}
	scopes := o.cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"email", "profile"}
	}
	o.provider = p
	o.oauth = &oauth2.Config{ClientID: o.cfg.ClientID, ClientSecret: o.cfg.ClientSecret, Endpoint: p.Endpoint(), RedirectURL: o.cfg.RedirectURL,
		Scopes: append([]string{oidc.ScopeOpenID}, scopes...)}
	o.verifier = p.Verifier(&oidc.Config{ClientID: o.cfg.ClientID})
	return nil
}

func (o *oidcProvider) key() []byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.cfg.CookieSecret) > 0 {
		return o.cfg.CookieSecret
	}
	if o.secret == nil {
		o.secret = make([]byte, 32)
		_, _ = rand.Read(o.secret)
	}
	return o.secret
}

type oidcState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Next     string `json:"x"`
	Exp      int64  `json:"e"`
}

const oidcCookie = "ledger_oidc"

func seal(key []byte, v any) string {
	b, _ := json.Marshal(v)
	p := base64.RawURLEncoding.EncodeToString(b)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("oidc-state:" + p))
	return p + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func unseal(key []byte, c string, v any) error {
	p, sig, ok := strings.Cut(c, ".")
	if !ok {
		return errors.New("malformed")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("oidc-state:" + p))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))) != 1 {
		return errors.New("bad signature")
	}
	b, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// HandleOIDCLogin (GET /auth/login) redirects to the identity provider.
func (a *Authenticator) HandleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	o := a.oidc
	if o == nil {
		loginFail(w, r, "SSO is not configured on this server")
		return
	}
	if err := o.init(r.Context()); err != nil {
		a.Cfg.Logger.Printf("ledgerd: %v", err)
		loginFail(w, r, "SSO provider unreachable")
		return
	}
	st := oidcState{State: RandToken(24), Nonce: RandToken(24), Verifier: oauth2.GenerateVerifier(), Next: SafeNext(r.URL.Query().Get("next")),
		Exp: a.Cfg.Now().Add(10 * time.Minute).Unix()}
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: seal(o.key(), st), Path: "/auth/", MaxAge: 600, HttpOnly: true, Secure: a.secure(r), SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, o.oauth.AuthCodeURL(st.State, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier)), http.StatusFound)
}

func hasEmail(list []string, email string) bool {
	for _, a := range list {
		if email != "" && strings.EqualFold(strings.TrimSpace(a), email) {
			return true
		}
	}
	return false
}

// HandleOIDCCallback (GET /auth/callback) completes the flow and starts a session.
func (a *Authenticator) HandleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	o := a.oidc
	if o == nil {
		loginFail(w, r, "SSO is not configured on this server")
		return
	}
	c, err := r.Cookie(oidcCookie)
	var st oidcState
	if err != nil || unseal(o.key(), c.Value, &st) != nil || a.Cfg.Now().Unix() > st.Exp {
		loginFail(w, r, "login session expired; try again")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: "", Path: "/auth/", MaxAge: -1, HttpOnly: true, Secure: a.secure(r)})
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		loginFail(w, r, "identity provider returned: "+e)
		return
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.State)) != 1 {
		loginFail(w, r, "state mismatch")
		return
	}
	if err := o.init(r.Context()); err != nil {
		loginFail(w, r, "SSO provider unreachable")
		return
	}
	ctx := o.ctx(r.Context())
	tok, err := o.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(st.Verifier))
	if err != nil {
		a.Cfg.Logger.Printf("ledgerd: oidc exchange: %v", err)
		loginFail(w, r, "code exchange failed")
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		loginFail(w, r, "no id_token in token response")
		return
	}
	idt, err := o.verifier.Verify(ctx, raw)
	if err != nil {
		a.Cfg.Logger.Printf("ledgerd: oidc verify: %v", err)
		loginFail(w, r, "id_token verification failed")
		return
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(st.Nonce)) != 1 {
		loginFail(w, r, "nonce mismatch")
		return
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
		Name          string `json:"name"`
		PreferredUser string `json:"preferred_username"`
	}
	if err := idt.Claims(&claims); err != nil {
		loginFail(w, r, "bad claims")
		return
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if claims.EmailVerified != nil && !*claims.EmailVerified {
		loginFail(w, r, "email address not verified by identity provider")
		return
	}
	// An email only confers anything (domain allow-list, admin/auditor grants) when the IdP
	// vouches for it; otherwise anyone able to set an arbitrary email at the IdP could claim
	// an admin's address.
	verified := (claims.EmailVerified != nil && *claims.EmailVerified) || o.cfg.TrustUnverifiedEmail
	if len(o.cfg.AllowDomains) > 0 {
		if !verified {
			loginFail(w, r, "identity provider did not mark the email address as verified")
			return
		}
		ok := false
		for _, d := range o.cfg.AllowDomains {
			if d = strings.ToLower(strings.TrimSpace(d)); d != "" && strings.HasSuffix(email, "@"+d) {
				ok = true
			}
		}
		if !ok {
			loginFail(w, r, "your email domain is not allowed")
			return
		}
	}
	role, force := o.cfg.DefaultRole, false
	if role == "" || role == RoleWriter || !ValidRole(role) {
		role = RoleViewer
	}
	if verified {
		if hasEmail(o.cfg.AuditorEmails, email) {
			role, force = RoleAuditor, true
		}
		if hasEmail(o.cfg.AdminEmails, email) {
			role, force = RoleAdmin, true
		}
	}
	name := claims.Name
	if name == "" {
		name = claims.PreferredUser
	}
	u, err := a.Store.UpsertOIDCUser(r.Context(), idt.Issuer, idt.Subject, email, name, role, force)
	if err != nil {
		a.Cfg.Logger.Printf("ledgerd: upsert user: %v", err)
		loginFail(w, r, "could not create user")
		return
	}
	if u.Disabled {
		loginFail(w, r, "your account is disabled")
		return
	}
	if err := a.StartSession(w, r, "user", u.ID); err != nil {
		loginFail(w, r, "could not start session")
		return
	}
	http.Redirect(w, r, SafeNext(st.Next), http.StatusSeeOther)
}
