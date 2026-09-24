package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// fakeIssuer is a minimal in-process OIDC provider enforcing PKCE S256 and signing RS256 ID tokens.
type fakeIssuer struct {
	srv                 *httptest.Server
	key                 *rsa.PrivateKey
	mu                  sync.Mutex
	codes               map[string][4]string // challenge, method, nonce, redirect
	email, sub          string
	verified            any // true | false | nil (claim omitted)
	wrongNonce, pkceBad bool
	sawPKCE             bool
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	f := &fakeIssuer{key: k, codes: map[string][4]string{}, email: "carol@example.com", sub: "sub-carol", verified: true}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize", "token_endpoint": f.srv.URL + "/token",
			"jwks_uri": f.srv.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}, "response_types_supported": []string{"code"},
			"subject_types_supported": []string{"public"}, "code_challenge_methods_supported": []string{"S256"}})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("response_type") != "code" || q.Get("client_id") != "ledger" || !strings.Contains(q.Get("scope"), "openid") {
			http.Error(w, "bad authorize request", 400)
			return
		}
		code := RandToken(16)
		f.mu.Lock()
		f.codes[code] = [4]string{q.Get("code_challenge"), q.Get("code_challenge_method"), q.Get("nonce"), q.Get("redirect_uri")}
		f.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		id, secret, ok := r.BasicAuth()
		if !ok {
			id, secret = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
		}
		if id != "ledger" || secret != "s3cret" {
			http.Error(w, `{"error":"invalid_client"}`, 401)
			return
		}
		f.mu.Lock()
		ar, ok := f.codes[r.PostFormValue("code")]
		delete(f.codes, r.PostFormValue("code"))
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
		if !ok || ar[3] != r.PostFormValue("redirect_uri") || ar[1] != "S256" || base64.RawURLEncoding.EncodeToString(sum[:]) != ar[0] || f.pkceBad {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		f.mu.Lock()
		f.sawPKCE = true
		f.mu.Unlock()
		nonce := ar[2]
		if f.wrongNonce {
			nonce = "other"
		}
		now := time.Now()
		claims := map[string]any{"iss": f.srv.URL, "sub": f.sub, "aud": "ledger", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": nonce, "email": f.email, "name": "Carol"}
		if f.verified != nil {
			claims["email_verified"] = f.verified
		}
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: f.key, KeyID: "k1"}}, nil)
		payload, _ := json.Marshal(claims)
		jws, _ := signer.Sign(payload)
		tok, _ := jws.CompactSerialize()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": tok})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

type oidcEnv struct {
	a  *Authenticator
	ts *httptest.Server
	f  *fakeIssuer
	st *Memory
}

func newOIDCEnv(t *testing.T, cfg OIDCConfig) *oidcEnv {
	f := newFakeIssuer(t)
	st := NewMemory()
	e := &oidcEnv{f: f, st: st}
	mux := http.NewServeMux()
	e.ts = httptest.NewServer(mux)
	t.Cleanup(e.ts.Close)
	cfg.Issuer, cfg.ClientID, cfg.ClientSecret, cfg.RedirectURL = f.srv.URL, "ledger", "s3cret", e.ts.URL+"/auth/callback"
	e.a = New(Config{OIDC: &cfg, HTTPClient: f.srv.Client()}, st)
	mux.HandleFunc("GET /auth/login", e.a.HandleOIDCLogin)
	mux.HandleFunc("GET /auth/callback", e.a.HandleOIDCCallback)
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "login page") })
	mux.HandleFunc("GET /whoami", e.a.Require(PermView, true, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(FromContext(r.Context()))
	}))
	mux.HandleFunc("GET /admin", e.a.Require(PermAdmin, true, func(w http.ResponseWriter, r *http.Request) {}))
	return e
}

func (e *oidcEnv) login(t *testing.T, next string) (*http.Client, *http.Response) {
	jar, _ := cookiejar.New(nil)
	br := &http.Client{Jar: jar}
	resp, err := br.Get(e.ts.URL + "/auth/login?next=" + url.QueryEscape(next))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return br, resp
}

func TestOIDCLoginRolesAndPKCE(t *testing.T) {
	e := newOIDCEnv(t, OIDCConfig{AdminEmails: []string{"Carol@Example.com"}, AuditorEmails: []string{"dave@example.com"}})
	br, resp := e.login(t, "/whoami")
	if resp.Request.URL.Path != "/whoami" || resp.StatusCode != 200 || !e.f.sawPKCE {
		t.Fatalf("landed %s %d pkce=%v", resp.Request.URL, resp.StatusCode, e.f.sawPKCE)
	}
	users, _ := e.st.ListUsers(context.Background())
	if len(users) != 1 || users[0].Role != RoleAdmin || users[0].Email != "carol@example.com" {
		t.Fatalf("users %+v", users)
	}
	if r, _ := br.Get(e.ts.URL + "/admin"); r.StatusCode != 200 {
		t.Fatal("admin via SSO")
	}
	// demotion takes effect on the next request; disabling kills the session
	_ = e.st.SetUserRole(context.Background(), users[0].ID, RoleViewer)
	if r, _ := br.Get(e.ts.URL + "/admin"); r.StatusCode != 403 {
		t.Fatal("demotion not enforced")
	}
	_ = e.st.SetUserDisabled(context.Background(), users[0].ID, true)
	if r, _ := br.Get(e.ts.URL + "/whoami"); r.StatusCode != 401 {
		t.Fatal("disabled user keeps session")
	}
	// auditor grant; unknown users get viewer
	e.f.email, e.f.sub = "dave@example.com", "sub-dave"
	e.login(t, "/")
	e.f.email, e.f.sub = "erin@example.com", "sub-erin"
	e.login(t, "/")
	users, _ = e.st.ListUsers(context.Background())
	roles := map[string]string{}
	for _, u := range users {
		roles[u.Email] = u.Role
	}
	if roles["dave@example.com"] != RoleAuditor || roles["erin@example.com"] != RoleViewer {
		t.Fatalf("roles %v", roles)
	}
}

func TestOIDCEmailVerifiedRequiredForGrants(t *testing.T) {
	e := newOIDCEnv(t, OIDCConfig{AdminEmails: []string{"carol@example.com"}})
	e.f.verified = nil // IdP omits email_verified: sign-in allowed, but no admin grant
	_, resp := e.login(t, "/whoami")
	if resp.Request.URL.Path != "/whoami" {
		t.Fatalf("landed %s", resp.Request.URL)
	}
	users, _ := e.st.ListUsers(context.Background())
	if users[0].Role != RoleViewer {
		t.Fatalf("unverified email got %s", users[0].Role)
	}
	e.f.verified, e.f.sub = false, "sub-2"
	_, resp = e.login(t, "/whoami")
	if resp.Request.URL.Path != "/login" || !strings.Contains(resp.Request.URL.RawQuery, "verified") {
		t.Fatalf("email_verified=false accepted: %s", resp.Request.URL)
	}
	// domain allow-list also needs a verified email
	d := newOIDCEnv(t, OIDCConfig{AllowDomains: []string{"example.com"}})
	d.f.verified = nil
	if _, resp := d.login(t, "/"); !strings.Contains(resp.Request.URL.RawQuery, "verified") {
		t.Fatalf("unverified domain match accepted: %s", resp.Request.URL)
	}
	d.f.verified, d.f.email = true, "m@evil.test"
	if _, resp := d.login(t, "/"); !strings.Contains(resp.Request.URL.RawQuery, "domain") {
		t.Fatalf("foreign domain accepted: %s", resp.Request.URL)
	}
}

func TestOIDCRejectsTampering(t *testing.T) {
	e := newOIDCEnv(t, OIDCConfig{})
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, _ := c.Get(e.ts.URL + "/auth/callback?code=x&state=y")
	if resp.StatusCode != 303 || !strings.Contains(resp.Header.Get("Location"), "expired") {
		t.Fatalf("no state cookie: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	e.f.wrongNonce = true
	if _, r := e.login(t, "/"); !strings.Contains(r.Request.URL.RawQuery, "nonce") {
		t.Fatalf("nonce mismatch accepted: %s", r.Request.URL)
	}
	e.f.wrongNonce, e.f.pkceBad = false, true
	if _, r := e.login(t, "/"); !strings.Contains(r.Request.URL.RawQuery, "exchange") {
		t.Fatalf("pkce failure accepted: %s", r.Request.URL)
	}
	e.f.pkceBad = false
	jar, _ := cookiejar.New(nil)
	br := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		if strings.HasPrefix(req.URL.String(), e.ts.URL+"/auth/callback") {
			q := req.URL.Query()
			q.Set("state", "tampered")
			req.URL.RawQuery = q.Encode()
		}
		return nil
	}}
	r, _ := br.Get(e.ts.URL + "/auth/login")
	if !strings.Contains(r.Request.URL.RawQuery, "state+mismatch") {
		t.Fatalf("state tamper accepted: %s", r.Request.URL)
	}
	// open redirect via next is neutralised
	_, r = e.login(t, "//evil.example/x")
	if r.Request.URL.Host != strings.TrimPrefix(e.ts.URL, "http://") {
		t.Fatalf("redirected off-site: %s", r.Request.URL)
	}
}

func TestOIDCIssuerDown(t *testing.T) {
	a := New(Config{OIDC: &OIDCConfig{Issuer: "http://127.0.0.1:1", ClientID: "x", RedirectURL: "http://h/auth/callback"}}, NewMemory())
	rr := httptest.NewRecorder()
	a.HandleOIDCLogin(rr, httptest.NewRequest("GET", "/auth/login", nil))
	if rr.Code != 303 || !strings.Contains(rr.Header().Get("Location"), "unreachable") {
		t.Fatalf("%d %s", rr.Code, rr.Header().Get("Location"))
	}
}
