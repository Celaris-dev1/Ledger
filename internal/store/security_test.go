package store

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestDuplicateKeysRejected(t *testing.T) {
	for _, p := range []string{
		`{"approved":false,"approved":true}`,
		`{"a":{"x":1,"x":2}}`,
		`[{"k":1},{"k":1,"k":2}]`, // escaped spelling of the same key
	} {
		r := AppendRequest{Chain: "c", Type: "t", ActorChain: []Actor{{Kind: "human", ID: "h"}}, Payload: []byte(p)}
		var ve *ValidationError
		if err := r.Validate(); !errors.As(err, &ve) || !strings.Contains(ve.Msg, "duplicate") {
			t.Errorf("%s: got %v, want duplicate-key validation error", p, err)
		}
	}
	ok := AppendRequest{Chain: "c", Type: "t", ActorChain: []Actor{{Kind: "human", ID: "h"}}, Payload: []byte(`{"a":{"x":1},"b":{"x":1},"c":[1,{"x":2}]}`)}
	if err := ok.Validate(); err != nil {
		t.Fatalf("distinct keys in different objects rejected: %v", err)
	}
}

func TestCheckCanonical(t *testing.T) {
	r := Record{ActorChain: []byte(`[{"id":"h","kind":"human"}]`), Payload: []byte(`{"a":1,"b":"<x>"}`)}
	if err := CheckCanonical(&r); err != nil {
		t.Fatalf("canonical record flagged: %v", err)
	}
	for _, p := range []string{`{"b":"<x>","a":1}`, `{"a":1, "b":"<x>"}`, `{"a":0,"a":1,"b":"<x>"}`, "{\"a\":1,\"b\":\"\\u003cx>\"}"} {
		r.Payload = []byte(p)
		var nc *NonCanonicalError
		if err := CheckCanonical(&r); !errors.As(err, &nc) {
			t.Errorf("%s: not flagged (%v)", p, err)
		}
	}
}

// Regression: a DB-level edit that keeps the canonical meaning but changes the stored text
// (here a duplicate key whose last value is the original) used to verify, so the UI and any
// first-key-wins parser showed "approved":false on a verified record.
func TestVerifyRejectsNonCanonicalStoredText(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if _, err := s.Append(ctx, req("warrant", "approval.decided", "", `{"approved":true}`)); err != nil {
		t.Fatal(err)
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Skipf("cannot bypass trigger (need superuser): %v", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE records SET payload='{"approved":false,"approved":true}' WHERE chain='warrant' AND seq=1`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	recs, _ := s.ChainRecords(ctx, "warrant")
	if h, _ := ComputeHash(&recs[0]); h != recs[0].Hash {
		t.Fatalf("precondition: tampered text should still hash identically")
	}
	res, err := s.Verify(ctx, "warrant")
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || !strings.Contains(res.Reason, "canonical") {
		t.Fatalf("non-canonical stored payload verified: %+v", res)
	}
}

// Regression: TRUNCATE bypassed the row-level append-only triggers on anchors/audit_events.
func TestEvidenceTablesRejectTruncate(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	for _, tbl := range []string{"records", "anchors", "anchor_receipts", "audit_events"} {
		if _, err := s.Pool.Exec(ctx, "TRUNCATE "+tbl+" CASCADE"); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("TRUNCATE %s: got %v, want append-only rejection", tbl, err)
		}
	}
}

// Regression: a retry that reused an idempotency_key with a different body used to get the
// first record back with 201, silently dropping the second event.
func TestIdempotencyKeyMismatchConflicts(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	a := req("bench", "bench.task.mined", "", `{"n":1}`)
	a.IdempotencyKey = "k1"
	first, err := s.Append(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.Append(ctx, a)
	if err != nil || again.ID != first.ID {
		t.Fatalf("identical retry: %v %v", again, err)
	}
	b := a
	b.Payload = []byte(`{"n":2}`)
	var ce *ConflictError
	if _, err := s.Append(ctx, b); !errors.As(err, &ce) {
		t.Fatalf("different payload under same key: got %v, want ConflictError", err)
	}
	c := a
	c.Type = "bench.run.scored"
	if _, err := s.Append(ctx, c); !errors.As(err, &ce) {
		t.Fatalf("different type under same key: got %v, want ConflictError", err)
	}
	if res, _ := s.Verify(ctx, "bench"); !res.OK || res.Length != 1 {
		t.Fatalf("chain changed: %+v", res)
	}
}
