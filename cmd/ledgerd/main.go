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
	"github.com/Celaris-dev1/Ledger/internal/store"
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
	srv := &http.Server{
		Addr:              addr,
		Handler:           (&api.Server{Store: st, Token: os.Getenv("LEDGER_TOKEN"), Key: key, Anchors: anchorSvc}).Handler(),
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
