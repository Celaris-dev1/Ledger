// Package storetest opens a Postgres store in a throwaway schema for tests.
package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/Celaris-dev1/Ledger/internal/store"
)

// Open skips the test unless LEDGER_TEST_DATABASE_URL is set; the schema is dropped on cleanup.
func Open(t testing.TB) *store.Store {
	t.Helper()
	s, _ := OpenURL(t)
	return s
}

// OpenURL is Open that also returns the schema-scoped URL (for opening a second store).
func OpenURL(t testing.TB) (*store.Store, string) {
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
	u, _ := url.Parse(base)
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	s, err := store.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Close()
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
		admin.Close(ctx)
	})
	return s, u.String()
}
