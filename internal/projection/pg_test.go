package projection

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/store"
	"github.com/Celaris-dev1/Ledger/internal/testfix"
	"github.com/jackc/pgx/v5"
)

// testStore opens a store in a throwaway schema. Skips unless LEDGER_TEST_DATABASE_URL is set.
func testStore(t *testing.T) *store.Store {
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
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		admin.Close(context.Background())
	})
	return s
}

func allFixtureRecords() []store.Record {
	var out []store.Record
	names := []string{}
	ss := streams()
	for n := range ss {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		out = append(out, ss[n].Recs...)
	}
	return append(out, testfix.MultiProduct().Recs...)
}

func TestPGRebuildEqualsIncremental(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	p := &PG{Pool: s.Pool, Batch: 3}
	for i, r := range allFixtureRecords() {
		if _, err := s.Append(ctx, testfix.Request(r)); err != nil {
			t.Fatal(err)
		}
		if i%4 == 0 {
			if _, err := p.CatchUp(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	st, err := p.CatchUp(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Rebuilt {
		t.Fatal("unexpected rebuild")
	}
	if st, _ := p.CatchUp(ctx); st.Records != 0 {
		t.Fatalf("catch-up not idempotent: %+v", st)
	}
	if d, err := p.Check(ctx); err != nil || d != "" {
		t.Fatalf("stored != in-memory projection: %v %s", err, d)
	}
	incr, err := p.Rows(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	rebuilt, _ := p.Rows(ctx, "")
	if d := Diff(incr, rebuilt); d != "" {
		t.Fatalf("rebuild != incremental: %s", d)
	}
	// Version change triggers an automatic rebuild.
	_, _ = s.Pool.Exec(ctx, `UPDATE projection_meta SET version=0`)
	if st, err := p.CatchUp(ctx); err != nil || !st.Rebuilt {
		t.Fatalf("version mismatch did not rebuild: %+v %v", st, err)
	}

	// Semantics survive the round trip through Postgres.
	r, _ := p.Rows(ctx, "g-ledger")
	tree, ok := BuildTree(r, "g-ledger")
	if !ok || len(tree.Steps) != 2 || len(tree.Steps[1].Attempts) != 1 || tree.Steps[1].Attempts[0].Approval != "approved" {
		t.Fatalf("tree: %+v", tree)
	}
	if tree.Steps[1].Attempts[0].Evidence[0].Hash == "" {
		t.Fatal("evidence hash missing")
	}
	bs := Budgets(r, "g-ledger")
	if len(bs) != 1 || !bs[0].Overspent || bs[0].Lines[2].Balance > -4.98 {
		t.Fatalf("budget: %+v", bs)
	}
	var mism int
	_ = s.Pool.QueryRow(ctx, `SELECT count(*) FROM approval_decisions WHERE NOT matched`).Scan(&mism)
	if mism != 0 {
		t.Fatalf("unexpected unmatched decisions: %d", mism)
	}
}

func TestPGApprovalBinding(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	p := &PG{Pool: s.Pool}
	b := testfix.New()
	actX := map[string]any{"tool": "wire", "amount": 10}
	actY := map[string]any{"tool": "wire", "amount": 10000}
	b.Add("ledger", "ledger.approval.requested", "g", A("alice", "bot"), map[string]any{"request_id": "r1", "action": actY})
	b.Add("ledger", "ledger.approval.granted", "g", A("alice"), map[string]any{"request_id": "r1", "action": actX})
	for _, r := range b.Recs {
		if _, err := s.Append(ctx, testfix.Request(r)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.CatchUp(ctx); err != nil {
		t.Fatal(err)
	}
	var decision *string
	var matched bool
	_ = s.Pool.QueryRow(ctx, `SELECT decision FROM approval_requests WHERE request_key='r1'`).Scan(&decision)
	_ = s.Pool.QueryRow(ctx, `SELECT matched FROM approval_decisions WHERE request_key='r1'`).Scan(&matched)
	if decision != nil || matched {
		t.Fatalf("approval for another hash satisfied the request: %v %v", decision, matched)
	}
}

// The async worker keeps up with concurrent appends and ends equal to a rebuild.
func TestPGWorkerConcurrent(t *testing.T) {
	s := testStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &PG{Pool: s.Pool, Batch: 7}
	w := NewWorker(p)
	w.Interval = 50 * time.Millisecond
	w.Logf = t.Logf
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	recs := allFixtureRecords()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			for j := k; j < len(recs); j += 4 {
				if _, err := s.Append(ctx, testfix.Request(recs[j])); err != nil {
					t.Error(err)
				}
				w.Notify()
			}
		}(i)
	}
	wg.Wait()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var pending int
		_ = s.Pool.QueryRow(ctx, `SELECT count(*) FROM records r LEFT JOIN projection_cursors c ON c.chain=r.chain WHERE r.seq > COALESCE(c.seq,0)`).Scan(&pending)
		if pending == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("worker did not catch up: %d pending", pending)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if d, err := p.Check(context.Background()); err != nil || d != "" {
		t.Fatalf("after concurrent projection: %v %s", err, d)
	}
}
