package web

import (
	"context"
	"testing"

	"github.com/Celaris-dev1/Ledger/internal/auth"
)

// Regression: with LEDGER_TOKENS (multi-tenancy) and no LEDGER_TOKEN/SSO/API tokens, auth
// auto mode used to resolve to open, so the UI, /v1/stream and /admin served every tenant's
// records (and admin token minting) to anonymous callers. Tenant tokens only authenticate the
// tenant-scoped API routes, so tenancy must never run open.
func TestTenancyNeverOpen(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	c, err := ConfigFromEnv(env(map[string]string{"LEDGER_TOKENS": "tokA=acme,ops=*"}))
	if err != nil {
		t.Fatal(err)
	}
	open, err := c.ResolveOpen(context.Background(), auth.NewMemory())
	if err != nil || open {
		t.Fatalf("tenancy in auto mode resolved open=%v err=%v; want closed", open, err)
	}
	c, err = ConfigFromEnv(env(map[string]string{"LEDGER_TOKENS": "tokA=acme", "LEDGER_AUTH": "off"}))
	if err != nil {
		t.Fatal(err)
	}
	if open, err := c.ResolveOpen(context.Background(), auth.NewMemory()); err == nil || open {
		t.Fatalf("LEDGER_AUTH=off with tenancy: open=%v err=%v; want refusal", open, err)
	}
	// unchanged without tenancy
	c, _ = ConfigFromEnv(env(map[string]string{}))
	if open, err := c.ResolveOpen(context.Background(), auth.NewMemory()); err != nil || !open {
		t.Fatalf("unconfigured ledgerd should stay open (dev mode): open=%v err=%v", open, err)
	}
}
