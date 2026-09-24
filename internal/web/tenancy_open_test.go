package web

import (
	"context"
	"strings"
	"testing"
)

// Regression (e2e suite): with LEDGER_TOKENS set and no API tokens/SSO/LEDGER_TOKEN, ledgerd
// resolved "open mode", so the UI and GET /v1/stream served every tenant's records to anonymous
// callers and to tenant tokens (which the RBAC layer treats as unknown bearers → anonymous).
func TestTenancyNeverOpen(t *testing.T) {
	for _, mode := range []string{"", "auto", "off"} {
		env := map[string]string{"LEDGER_TOKENS": "a=acme,b=globex", "LEDGER_AUTH": mode}
		c, err := ConfigFromEnv(func(k string) string { return env[k] })
		if err != nil {
			t.Fatal(err)
		}
		open, err := c.ResolveOpen(context.Background(), nil)
		if err != nil || open {
			t.Fatalf("LEDGER_AUTH=%q with tenancy: open=%v err=%v", mode, open, err)
		}
		if mode == "off" && !strings.Contains(strings.Join(c.Warnings, "\n"), "LEDGER_AUTH=off ignored") {
			t.Fatalf("no warning for LEDGER_AUTH=off with tenancy: %v", c.Warnings)
		}
	}
	// Without tenancy nothing changes: nothing configured is still open.
	c, _ := ConfigFromEnv(func(string) string { return "" })
	if open, _ := c.ResolveOpen(context.Background(), nil); !open {
		t.Fatal("no configuration should still be open mode")
	}
}
