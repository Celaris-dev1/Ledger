// Package web is the auditor-facing UI served by ledgerd: server-rendered html/template pages
// plus a little vanilla JS (live replay timeline, in-browser hash re-verification), all
// embedded, no build step. It also serves GET /v1/stream (Server-Sent Events).
//
// Every untrusted value (record payloads, ids, actor names) is rendered through html/template
// or DOM textContent, the Content-Security-Policy forbids inline script and style, and every
// page is behind the auth package's role checks.
package web

import (
	"context"
	"embed"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/anchoring"
	"github.com/Celaris-dev1/Ledger/internal/api"
	"github.com/Celaris-dev1/Ledger/internal/auth"
	"github.com/Celaris-dev1/Ledger/internal/projection"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// StaticFS exposes the embedded assets (the canonicalisation golden test loads canon.js).
func StaticFS() fs.FS { sub, _ := fs.Sub(staticFS, "static"); return sub }

// Backend is the record store the UI reads (the API backend plus chain listing).
type Backend interface {
	api.Backend
	Chains(ctx context.Context) ([]string, error)
}

// ReceiptSource lists stored external anchor receipts (*anchoring.Service).
type ReceiptSource interface {
	Receipts(ctx context.Context, chain string) ([]anchoring.StoredReceipt, error)
}

// Server is the UI.
type Server struct {
	Store       Backend
	Projections projection.Reader // nil: goal pages fall back to raw replay
	Receipts    ReceiptSource     // nil: anchoring shown as not configured
	Auth        *auth.Authenticator
	API         http.Handler // the /v1 API, mounted under the same mux
	Stream      *Streamer    // GET /v1/stream (nil: 501)
	Logger      *log.Logger
	// Now is overridable for tests.
	Now func() time.Time

	vmu   sync.Mutex
	vcach map[string]verifyEntry
}

const verifyTTL = 30 * time.Second

type verifyEntry struct {
	at   time.Time
	seq  int64
	head string
	res  store.VerifyResult
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) logf(f string, a ...any) {
	if s.Logger != nil {
		s.Logger.Printf(f, a...)
	} else {
		log.Printf(f, a...)
	}
}

// Handler returns the full ledgerd handler: UI pages, static assets, auth endpoints,
// /v1/stream, and the API for every other /v1 route, all wrapped in security headers.
func (s *Server) Handler() http.Handler {
	a := s.Auth
	if a.Denied == nil {
		a.Denied = s.denied
	}
	mux := http.NewServeMux()
	view := func(h http.HandlerFunc) http.HandlerFunc { return a.Require(auth.PermView, false, h) }
	st, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", staticHandler(st)))
	mux.HandleFunc("GET /{$}", view(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/chains", http.StatusSeeOther) }))
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("GET /auth/login", a.HandleOIDCLogin)
	mux.HandleFunc("GET /auth/callback", a.HandleOIDCCallback)
	mux.HandleFunc("POST /auth/token", a.HandleTokenLogin)
	mux.HandleFunc("POST /auth/logout", a.Require(auth.PermRead, false, a.HandleLogout))
	mux.HandleFunc("GET /chains", view(s.chains))
	mux.HandleFunc("GET /chains/{chain}", view(s.chainRecords))
	mux.HandleFunc("GET /goals", view(s.goals))
	mux.HandleFunc("GET /goals/{goal_id}", view(s.goal))
	mux.HandleFunc("GET /approvals", view(s.approvals))
	mux.HandleFunc("GET /budgets", view(s.budgets))
	mux.HandleFunc("GET /incidents/{goal_id}", view(s.incident))
	mux.HandleFunc("GET /r/{chain}/{seq}", view(s.record))
	mux.HandleFunc("GET /ui/api/status", view(s.status))
	mux.HandleFunc("GET /admin", a.Require(auth.PermAdmin, false, s.admin))
	mux.HandleFunc("POST /admin/tokens", a.Require(auth.PermAdmin, false, s.createToken))
	mux.HandleFunc("POST /admin/tokens/{id}/revoke", a.Require(auth.PermAdmin, false, s.revokeToken))
	mux.HandleFunc("POST /admin/users/{id}", a.Require(auth.PermAdmin, false, s.updateUser))
	mux.HandleFunc("GET /v1/whoami", a.Require(auth.PermRead, true, s.whoami))
	if s.Stream != nil {
		mux.Handle("GET /v1/stream", a.Require(auth.PermView, true, s.Stream.ServeHTTP))
	} else {
		mux.HandleFunc("GET /v1/stream", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":"stream not configured"}`, http.StatusNotImplemented)
		})
	}
	if s.API != nil {
		mux.Handle("/v1/", s.API)
		mux.Handle("GET /healthz", s.API)
	}
	return SecurityHeaders(mux)
}

func staticHandler(fsys fs.FS) http.Handler {
	fh := http.FileServerFS(fsys)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" || strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		fh.ServeHTTP(w, r)
	})
}

// uiCSP is the policy for every UI page: no inline script or style, same-origin everything.
const uiCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
	"font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// apiCSP covers API responses, including the self-contained HTML exports (inline style only).
const apiCSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

// SecurityHeaders sets the security headers on every response.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		if strings.HasPrefix(r.URL.Path, "/v1/") || r.URL.Path == "/healthz" {
			h.Set("Content-Security-Policy", apiCSP)
		} else {
			h.Set("Content-Security-Policy", uiCSP)
			h.Set("Cache-Control", "no-store")
		}
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// APIOnly serves only the API (/v1/*, including the stream, and /healthz): LEDGER_UI=off.
func APIOnly(s *Server) http.Handler {
	h := s.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/") && r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// chainVerify verifies a chain, cached until its head moves.
func (s *Server) chainVerify(ctx context.Context, chain string) (store.VerifyResult, error) {
	seq, head, err := s.Store.Head(ctx, chain)
	if err != nil {
		return store.VerifyResult{}, err
	}
	s.vmu.Lock()
	e, ok := s.vcach[chain]
	s.vmu.Unlock()
	// cached until the head moves, and never longer than verifyTTL (so tampering with an old
	// row is picked up even on an idle chain)
	if ok && e.seq == seq && e.head == head && s.now().Sub(e.at) < verifyTTL {
		return e.res, nil
	}
	res, err := s.Store.Verify(ctx, chain)
	if err != nil {
		return res, err
	}
	s.vmu.Lock()
	if s.vcach == nil {
		s.vcach = map[string]verifyEntry{}
	}
	s.vcach[chain] = verifyEntry{s.now(), seq, head, res}
	s.vmu.Unlock()
	return res, nil
}
