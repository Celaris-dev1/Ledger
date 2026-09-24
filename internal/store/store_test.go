package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
)

// testStore opens a store in a throwaway schema. Skips unless LEDGER_TEST_DATABASE_URL is set.
func testStore(t *testing.T) *Store {
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
	s, err := Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Close()
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
		admin.Close(ctx)
	})
	return s
}

func req(chain, typ, goal string, payload string) AppendRequest {
	return AppendRequest{Chain: chain, Type: typ, GoalID: goal, PolicyVersion: "pol-1",
		ActorChain: []Actor{{Kind: "human", ID: "alice"}, {Kind: "agent", ID: "planner", Model: "m", ModelVersion: "2"}},
		Payload:    json.RawMessage(payload)}
}

func TestValidate(t *testing.T) {
	r := req("c", "t", "", `{}`)
	r.ActorChain = nil
	if r.Validate() == nil {
		t.Fatal("empty actor_chain accepted")
	}
	r = req("c", "t", "", `{}`)
	r.ActorChain = []Actor{{Kind: "agent", ID: "x"}}
	if r.Validate() == nil {
		t.Fatal("non-human first actor accepted")
	}
	r = req("c", "t", "", `{}`)
	r.ActorChain = append(r.ActorChain, Actor{Kind: "robot", ID: "y"})
	if r.Validate() == nil {
		t.Fatal("bad kind accepted")
	}
	r = req("c", "t", "", ``)
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAppendChainsAndVerifies(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	r1, err := s.Append(ctx, req("gate", "gate.run.started", "g1", `{"b":2,"a":1.50}`))
	if err != nil {
		t.Fatal(err)
	}
	r2, err := s.Append(ctx, req("gate", "gate.run.decided", "g1", `{"verdict":"pass"}`))
	if err != nil {
		t.Fatal(err)
	}
	if r1.Seq != 1 || r1.PrevHash != "" || r2.Seq != 2 || r2.PrevHash != r1.Hash {
		t.Fatalf("bad linkage: %+v %+v", r1, r2)
	}
	res, err := s.Verify(ctx, "gate")
	if err != nil || !res.OK || res.Length != 2 || res.Head != r2.Hash || res.BrokenAt != nil {
		t.Fatalf("verify: %+v %v", res, err)
	}
	recs, _ := s.Replay(ctx, "g1")
	if len(recs) != 2 || string(recs[0].Payload) != `{"a":1.50,"b":2}` {
		t.Fatalf("replay: %+v", recs)
	}
	var human string
	_ = s.Pool.QueryRow(ctx, `SELECT originating_human_id FROM goals WHERE id='g1'`).Scan(&human)
	if human != "alice" {
		t.Fatalf("goal projection: %q", human)
	}
}

func TestAppendIdempotencyKey(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	r1req := req("bench", "bench.task.mined", "g1", `{"n":1}`)
	r1req.IdempotencyKey = "key-1"
	r1, err := s.Append(ctx, r1req)
	if err != nil {
		t.Fatal(err)
	}
	// Retry with the same key: same chain must return the original record, not append a new one.
	r2req := req("bench", "bench.task.mined", "g1", `{"n":1}`)
	r2req.IdempotencyKey = "key-1"
	r2, err := s.Append(ctx, r2req)
	if err != nil {
		t.Fatal(err)
	}
	if r2.ID != r1.ID || r2.Seq != r1.Seq || r2.Hash != r1.Hash {
		t.Fatalf("retry did not return original record: %+v vs %+v", r1, r2)
	}
	res, err := s.Verify(ctx, "bench")
	if err != nil || res.Length != 1 {
		t.Fatalf("expected single record after retried append, got: %+v %v", res, err)
	}
	// A different key on the same chain appends normally.
	r3req := req("bench", "bench.run.scored", "g1", `{"n":2}`)
	r3req.IdempotencyKey = "key-2"
	r3, err := s.Append(ctx, r3req)
	if err != nil {
		t.Fatal(err)
	}
	if r3.Seq != 2 {
		t.Fatalf("expected seq 2 for distinct key, got %d", r3.Seq)
	}
	// The same key on a different chain does not collide.
	r4req := req("gate", "gate.run.started", "g2", `{}`)
	r4req.IdempotencyKey = "key-1"
	if _, err := s.Append(ctx, r4req); err != nil {
		t.Fatalf("same key on different chain should not collide: %v", err)
	}
}

func TestConcurrentAppendsSerialized(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Append(ctx, req("harbour", "harbour.effect.intent", "", `{}`)); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	res, _ := s.Verify(ctx, "harbour")
	if !res.OK || res.Length != 40 {
		t.Fatalf("verify after concurrent appends: %+v", res)
	}
}

func TestAppendOnlyTrigger(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	r, _ := s.Append(ctx, req("proof", "proof.fetch.captured", "", `{}`))
	for _, q := range []string{
		`UPDATE records SET payload='{"x":1}' WHERE id=$1`,
		`DELETE FROM records WHERE id=$1`,
	} {
		_, err := s.Pool.Exec(ctx, q, r.ID)
		if err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("%s: expected append-only rejection, got %v", q, err)
		}
	}
	if _, err := s.Pool.Exec(ctx, `TRUNCATE records CASCADE`); err == nil {
		t.Fatal("truncate allowed")
	}
}

// TestTamperDetected edits a stored row (bypassing the trigger as a DB superuser would) and
// proves verify pinpoints the altered record.
func TestTamperDetected(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := s.Append(ctx, req("warrant", "warrant.call.allowed", "", `{"amount":10}`)); err != nil {
			t.Fatal(err)
		}
	}
	if res, _ := s.Verify(ctx, "warrant"); !res.OK {
		t.Fatalf("pre-tamper verify failed: %+v", res)
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Skipf("cannot bypass trigger (need superuser): %v", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE records SET payload='{"amount":10000}' WHERE chain='warrant' AND seq=3`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	res, err := s.Verify(ctx, "warrant")
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.BrokenAt == nil || *res.BrokenAt != 3 {
		t.Fatalf("tamper not detected at seq 3: %+v", res)
	}

	// Recomputing the hash to hide the edit breaks the next link instead.
	recs, _ := s.ChainRecords(ctx, "warrant")
	forged, _ := ComputeHash(&recs[2])
	tx, _ = s.Pool.Begin(ctx)
	_, _ = tx.Exec(ctx, `SET LOCAL session_replication_role = replica`)
	if _, err := tx.Exec(ctx, `UPDATE records SET hash=$1 WHERE chain='warrant' AND seq=3`, forged); err != nil {
		t.Fatal(err)
	}
	_ = tx.Commit(ctx)
	res, _ = s.Verify(ctx, "warrant")
	if res.OK || *res.BrokenAt != 4 {
		t.Fatalf("forged hash not detected at seq 4: %+v", res)
	}
}

func TestTruncationDetectedByHead(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		_, _ = s.Append(ctx, req("bench", "bench.run.scored", "", `{}`))
	}
	tx, _ := s.Pool.Begin(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Skip(err)
	}
	_, _ = tx.Exec(ctx, `DELETE FROM records WHERE chain='bench' AND seq=3`)
	_ = tx.Commit(ctx)
	res, _ := s.Verify(ctx, "bench")
	if res.OK {
		t.Fatalf("tail truncation not detected: %+v", res)
	}
}
