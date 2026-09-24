// Command ledgerd serves the Ledger HTTP API.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/anchoring"
	"github.com/Celaris-dev1/Ledger/internal/api"
	"github.com/Celaris-dev1/Ledger/internal/auth"
	"github.com/Celaris-dev1/Ledger/internal/keys"
	"github.com/Celaris-dev1/Ledger/internal/projection"
	"github.com/Celaris-dev1/Ledger/internal/store"
	"github.com/Celaris-dev1/Ledger/internal/tenant"
	"github.com/Celaris-dev1/Ledger/internal/web"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	dbURL := env("LEDGER_DATABASE_URL", "postgres://postgres:postgres@localhost:5432/ledger?sslmode=disable")
	st, err := store.Open(ctx, dbURL)
	if err != nil {
		log.Fatalf("ledgerd: database: %v", err)
	}
	defer st.Close()
	key, keyring, err := anchor.LoadSigner(os.Getenv("LEDGER_SIGNING_KEY"), env("LEDGER_KEY_FILE", "ledger_ed25519.key"), os.Getenv("LEDGER_KEYRING_DIR"))
	if err != nil {
		log.Fatalf("ledgerd: signing key: %v", err)
	}
	acfg, err := anchoring.ConfigFromEnv(os.Getenv)
	if err != nil {
		log.Fatalf("ledgerd: anchoring: %v", err)
	}
	for _, w := range acfg.Warnings {
		log.Printf("ledgerd: anchoring: %s", w)
	}
	anchorSvc := acfg.Service(st, key, keyring, log.Default())
	if len(anchorSvc.Backends) > 0 && (acfg.Interval > 0 || acfg.EveryN > 0) {
		sched := &anchoring.Scheduler{Svc: anchorSvc, Interval: acfg.Interval, EveryN: acfg.EveryN, Poll: acfg.Poll}
		go sched.Run(ctx)
		log.Printf("ledgerd: anchoring every %s / %d records via %d backend(s)", acfg.Interval, acfg.EveryN, len(anchorSvc.Backends))
	} else {
		log.Printf("ledgerd: scheduled external anchoring disabled (set LEDGER_ANCHOR_INTERVAL or LEDGER_ANCHOR_EVERY and a backend)")
	}
	addr := env("LEDGER_ADDR", ":8410")
	apiSrv := &api.Server{Store: st, Token: os.Getenv("LEDGER_TOKEN"), Key: key, Anchors: anchorSvc}
	// Compliance/ops: multi-tenancy (LEDGER_TOKENS), payload envelope encryption
	// (LEDGER_DATA_KEY_DIR) and KMS/Vault root signing (LEDGER_SIGNER).
	if spec := os.Getenv("LEDGER_TOKENS"); spec != "" {
		toks, err := tenant.ParseTokens(spec)
		if err != nil {
			log.Fatalf("ledgerd: %v", err)
		}
		apiSrv.Tenants = toks
		apiSrv.TenantStore = func(t string) (api.Backend, error) { return tenant.New(st, t) }
		log.Printf("ledgerd: multi-tenancy on (%d tokens); LEDGER_TOKEN ignored", len(toks))
	}
	if d := os.Getenv("LEDGER_DATA_KEY_DIR"); d != "" {
		apiSrv.DataKeys = &keys.FileDataKeyStore{Dir: d}
	}
	if s := os.Getenv("LEDGER_SIGNER"); s != "" && s != "file" {
		sg, err := keys.SignerFromEnv(ctx, os.Getenv, key)
		if err != nil {
			log.Fatalf("ledgerd: signer: %v", err)
		}
		apiSrv.Signer = sg
		log.Printf("ledgerd: roots signed by %s key %s", s, sg.KeyID())
	}
	// Projections: async, bounded (one coalesced pending run) catch-up after each
	// append plus a periodic sweep. LEDGER_PROJECTIONS=off disables them.
	if os.Getenv("LEDGER_PROJECTIONS") != "off" {
		proj := &projection.PG{Pool: st.Pool}
		worker := projection.NewWorker(proj)
		go worker.Run(ctx)
		apiSrv.Projections = proj
		apiSrv.OnAppend = func(*store.Record) { worker.Notify() }
	}
	// Access control + web UI (internal/auth, internal/web; README "Web UI and access control").
	ucfg, err := web.ConfigFromEnv(os.Getenv)
	if err != nil {
		log.Fatalf("ledgerd: ui/auth: %v", err)
	}
	for _, w := range ucfg.Warnings {
		log.Printf("ledgerd: warning: %s", w)
	}
	authStore := &auth.PG{Pool: st.Pool}
	if ucfg.Auth.Open, err = ucfg.ResolveOpen(ctx, authStore); err != nil {
		log.Fatalf("ledgerd: auth: %v", err)
	}
	ucfg.Auth.Logger = log.Default()
	authn := auth.New(ucfg.Auth, authStore)
	apiSrv.Auth = authn
	if ucfg.Auth.Open {
		log.Printf("ledgerd: WARNING: open mode, authentication disabled (no LEDGER_TOKEN, SSO or API tokens; LEDGER_AUTH=on forces auth)")
	}
	hub := web.NewHub()
	go web.Listen(ctx, st.Pool, hub, log.Default())
	prevOnAppend := apiSrv.OnAppend
	apiSrv.OnAppend = func(r *store.Record) {
		if prevOnAppend != nil {
			prevOnAppend(r)
		}
		hub.Kick()
	}
	ui := &web.Server{Store: st, Projections: apiSrv.Projections, Auth: authn, API: apiSrv.Handler(), Logger: log.Default(),
		Stream: &web.Streamer{Src: &web.PGStream{Pool: st.Pool}, Hub: hub, Poll: ucfg.StreamPoll, Logger: log.Default()}}
	if len(anchorSvc.Backends) > 0 {
		ui.Receipts = anchorSvc
	}
	var handler http.Handler = ui.Handler()
	if !ucfg.UIEnabled {
		handler = web.APIOnly(ui)
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Printf("ledgerd listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
