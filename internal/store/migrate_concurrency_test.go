package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// freshSchemaURL creates an empty schema and returns a URL scoped to it (no migrations run).
func freshSchemaURL(t *testing.T) string {
	t.Helper()
	base := os.Getenv("LEDGER_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("LEDGER_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	var b [4]byte
	_, _ = rand.Read(b[:])
	schema := "ledger_test_" + hex.EncodeToString(b[:])
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
		admin.Close(ctx)
	})
	u, _ := url.Parse(base)
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String()
}

// Concurrent migrations on a fresh database (several ledgerd/CLI processes starting at once)
// must all succeed, and a later Open must not wait on a lock left behind by an earlier one.
func TestConcurrentMigrationsFreshDB(t *testing.T) {
	u := freshSchemaURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	stores := make([]*Store, 12)
	errs := make([]error, 12)
	for i := range stores {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			stores[i], errs[i] = Open(ctx, u)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
	}
	// the stores stay open (their pools keep idle connections); more opens must not block
	for i := 0; i < 4; i++ {
		octx, ocancel := context.WithTimeout(ctx, 10*time.Second)
		s, err := Open(octx, u)
		ocancel()
		if err != nil {
			t.Fatalf("re-open %d while other stores are open: %v", i, err)
		}
		// exercise the pool of each earlier store too (checks out several connections)
		for _, st := range stores {
			var n int
			if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil || n == 0 {
				t.Fatalf("migrations: %d %v", n, err)
			}
		}
		s.Close()
	}
	var locks int
	_ = stores[0].Pool.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND objid=8410001`).Scan(&locks)
	if locks != 0 {
		t.Fatalf("%d migration advisory locks still held after all migrations finished", locks)
	}
	for _, s := range stores {
		s.Close()
	}
}
