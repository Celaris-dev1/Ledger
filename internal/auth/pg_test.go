package auth

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/store"
	"github.com/jackc/pgx/v5"
)

func TestPGStore(t *testing.T) {
	base := os.Getenv("LEDGER_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("LEDGER_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	schema := "ledger_auth_test_" + RandToken(4)
	schema = "s" + HashSecret(schema)[:12]
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
	st, err := store.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		st.Close()
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
		admin.Close(ctx)
	})
	p := &PG{Pool: st.Pool}
	plain, tok, err := NewToken(ctx, p, "agent", RoleWriter, "test")
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.TokenByHash(ctx, HashSecret(plain))
	if err != nil || got == nil || got.ID != tok.ID || got.Hash == plain {
		t.Fatalf("lookup %+v %v", got, err)
	}
	if n, _ := p.CountActiveTokens(ctx); n != 1 {
		t.Fatalf("count %d", n)
	}
	_ = p.TouchToken(ctx, tok.ID, time.Now())
	if err := p.RevokeToken(ctx, tok.ID); err != nil {
		t.Fatal(err)
	}
	if n, _ := p.CountActiveTokens(ctx); n != 0 {
		t.Fatal("revoke")
	}
	if err := p.RevokeToken(ctx, "nope"); err != ErrNotFound {
		t.Fatalf("revoke missing: %v", err)
	}
	usr, err := p.UpsertOIDCUser(ctx, "iss", "sub", "A@x.test", "A", RoleViewer, false)
	if err != nil || usr.Email != "a@x.test" {
		t.Fatalf("%+v %v", usr, err)
	}
	u2, _ := p.UpsertOIDCUser(ctx, "iss", "sub", "a@x.test", "A", RoleAdmin, false)
	u3, _ := p.UpsertOIDCUser(ctx, "iss", "sub", "a@x.test", "A", RoleAdmin, true)
	if u2.ID != usr.ID || u2.Role != RoleViewer || u3.Role != RoleAdmin {
		t.Fatalf("upsert roles %s %s", u2.Role, u3.Role)
	}
	s := Session{Hash: HashSecret("x"), Kind: "user", SubjectID: usr.ID, CSRF: "c", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	if err := p.InsertSession(ctx, s); err != nil {
		t.Fatal(err)
	}
	if gs, _ := p.SessionByHash(ctx, s.Hash); gs == nil || gs.CSRF != "c" {
		t.Fatal("session")
	}
	_ = p.DeleteSession(ctx, s.Hash)
	if gs, _ := p.SessionByHash(ctx, s.Hash); gs != nil {
		t.Fatal("session delete")
	}
}
