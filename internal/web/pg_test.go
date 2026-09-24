package web

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/auth"
	"github.com/Celaris-dev1/Ledger/internal/store"
	"github.com/jackc/pgx/v5"
)

func TestPGStreamAndNotify(t *testing.T) {
	base := os.Getenv("LEDGER_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("LEDGER_TEST_DATABASE_URL not set")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	schema := "ledger_web_test_" + auth.HashSecret(auth.RandToken(8))[:10]
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
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		admin.Close(context.Background())
	})
	hub := NewHub()
	wake, stop := hub.Subscribe()
	defer stop()
	go Listen(ctx, st.Pool, hub, nil)
	time.Sleep(200 * time.Millisecond)
	add := func(chain, goal string) {
		if _, err := st.Append(ctx, store.AppendRequest{Chain: chain, Type: "t", GoalID: goal, ActorChain: []store.Actor{{Kind: "human", ID: "a"}}, Payload: []byte(`{"x":1.50}`)}); err != nil {
			t.Fatal(err)
		}
	}
	add("a", "g")
	select {
	case <-wake:
	case <-time.After(5 * time.Second):
		t.Fatal("no NOTIFY wake-up")
	}
	add("a", "other")
	add("b", "g")
	add("a", "g")
	src := &PGStream{Pool: st.Pool}
	heads, err := src.Heads(ctx)
	if err != nil || heads["a"] != 3 || heads["b"] != 1 {
		t.Fatalf("heads %v %v", heads, err)
	}
	per, err := src.Since(ctx, map[string]int64{"a": 1}, "", "g", 10)
	if err != nil || len(per["a"]) != 1 || per["a"][0].Seq != 3 || len(per["b"]) != 1 || string(per["a"][0].Payload) != `{"x":1.50}` {
		t.Fatalf("since %+v %v", per, err)
	}
	per, _ = src.Since(ctx, map[string]int64{}, "a", "", 2)
	if len(per["a"]) != 2 || per["b"] != nil {
		t.Fatalf("limit/chain filter %+v", per)
	}
}
