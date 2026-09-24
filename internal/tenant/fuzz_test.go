package tenant

import (
	"context"
	"math/rand"
	"strings"
	"testing"

	"github.com/Celaris-dev1/Ledger/internal/store"
	"github.com/Celaris-dev1/Ledger/internal/storetest"
)

// FuzzTenantMapping: a scoped store's physical chain name always belongs to its own tenant and
// maps back to the logical name; no logical name reaches another tenant's namespace.
func FuzzTenantMapping(f *testing.F) {
	for _, s := range [][2]string{{"acme", "gate"}, {"default", "t/globex/x"}, {"acme", "t/"}, {"default", "t//x"}, {"a", "../x"}, {"default", "T/acme/x"}, {"t", "t"}, {"acme", ""}} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, ten, chain string) {
		sc, err := New(nil, ten)
		if err != nil {
			if ValidID(ten) || ten == "" {
				t.Fatalf("valid tenant %q rejected", ten)
			}
			return
		}
		p, err := sc.Physical(chain)
		if err != nil {
			if !strings.HasPrefix(chain, "t/") {
				t.Fatalf("chain %q rejected", chain)
			}
			return
		}
		if got := store.TenantOfChain(p); got != sc.Tenant {
			t.Fatalf("tenant %q chain %q -> physical %q belongs to tenant %q", sc.Tenant, chain, p, got)
		}
		if Logical(p) != chain {
			t.Fatalf("logical(%q) = %q, want %q", p, Logical(p), chain)
		}
	})
}

// TestTenantOfMatchesSQL: the Go and SQL (ledger_tenant_of, which fills the indexed tenant
// column used by scoped reads) derivations agree on hostile chain names.
func TestTenantOfMatchesSQL(t *testing.T) {
	s := storetest.Open(t)
	names := []string{"", "t", "t/", "t//", "t//x", "t/a", "t/a/", "t/a/b", "t/a/b/c", "T/a/b", " t/a/b", "t/%/x", "t/_/x", "t/a%/x", "t/\\/x", "tt/a/b", "t/é/x", "t/a b/x"}
	rng := rand.New(rand.NewSource(1))
	alphabet := []string{"t", "/", "a", "%", "_", "\\", "é", " "}
	for i := 0; i < 2000; i++ {
		var b strings.Builder
		for j := rng.Intn(8); j >= 0; j-- {
			b.WriteString(alphabet[rng.Intn(len(alphabet))])
		}
		names = append(names, b.String())
	}
	for _, n := range names {
		var sqlT string
		if err := s.Pool.QueryRow(context.Background(), `SELECT ledger_tenant_of($1)`, n).Scan(&sqlT); err != nil {
			t.Fatal(err)
		}
		if goT := store.TenantOfChain(n); goT != sqlT {
			t.Fatalf("chain %q: Go tenant %q, SQL tenant %q", n, goT, sqlT)
		}
	}
}
