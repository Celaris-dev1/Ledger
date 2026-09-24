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
	"github.com/Celaris-dev1/Ledger/internal/api"
	"github.com/Celaris-dev1/Ledger/internal/projection"
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
	key, err := anchor.LoadKey(os.Getenv("LEDGER_SIGNING_KEY"), env("LEDGER_KEY_FILE", "ledger_ed25519.key"))
	if err != nil {
		log.Fatalf("ledgerd: signing key: %v", err)
	}
	addr := env("LEDGER_ADDR", ":8410")
	apiSrv := &api.Server{Store: st, Token: os.Getenv("LEDGER_TOKEN"), Key: key}
	// Projections: async, bounded (one coalesced pending run) catch-up after each
	// append plus a periodic sweep. LEDGER_PROJECTIONS=off disables them.
	if os.Getenv("LEDGER_PROJECTIONS") != "off" {
		proj := &projection.PG{Pool: st.Pool}
		worker := projection.NewWorker(proj)
		go worker.Run(ctx)
		apiSrv.Projections = proj
		apiSrv.OnAppend = func(*store.Record) { worker.Notify() }
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           apiSrv.Handler(),
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
