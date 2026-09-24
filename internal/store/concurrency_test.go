package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
)

func concReq(chain, key string, i int) AppendRequest {
	return AppendRequest{Chain: chain, Type: "conc.test", ActorChain: []Actor{{Kind: "human", ID: "alice"}, {Kind: "agent", ID: fmt.Sprintf("w%d", i%8)}},
		Payload: json.RawMessage(fmt.Sprintf(`{"i":%d}`, i)), IdempotencyKey: key, GoalID: fmt.Sprintf("g%d", i%3)}
}

// TestConcurrency64WritersSameChain: 64 writers × 20 appends on one chain; every append
// succeeds, seqs are contiguous and the chain verifies.
func TestConcurrency64WritersSameChain(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	const W, N = 64, 20
	var wg sync.WaitGroup
	errs := make(chan error, W*N)
	for w := 0; w < W; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < N; i++ {
				if _, err := s.Append(ctx, concReq("hot", "", w*N+i)); err != nil {
					errs <- err
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	res, err := s.Verify(ctx, "hot")
	if err != nil || !res.OK || res.Length != W*N {
		t.Fatalf("verify: %+v %v", res, err)
	}
}

// TestConcurrency64WritersManyChains: 64 writers spread over 16 chains (shared goals and
// operators, so the domain upserts contend too).
func TestConcurrency64WritersManyChains(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	const W, N, C = 64, 15, 16
	var wg sync.WaitGroup
	errs := make(chan error, W*N)
	for w := 0; w < W; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < N; i++ {
				if _, err := s.Append(ctx, concReq(fmt.Sprintf("c%02d", (w+i)%C), "", w*N+i)); err != nil {
					errs <- err
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	total := 0
	for c := 0; c < C; c++ {
		res, err := s.Verify(ctx, fmt.Sprintf("c%02d", c))
		if err != nil || !res.OK {
			t.Fatalf("chain %d: %+v %v", c, res, err)
		}
		total += res.Length
	}
	if total != W*N {
		t.Fatalf("%d records, want %d", total, W*N)
	}
}

// TestConcurrencyIdempotentRetriesRace: 32 clients retry the same (chain, key) at once, some
// with different payloads: exactly one record is created and every caller gets it.
func TestConcurrencyIdempotentRetriesRace(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	for round := 0; round < 5; round++ {
		key := fmt.Sprintf("k-%d", round)
		var wg sync.WaitGroup
		ids := make([]string, 32)
		errs := make([]error, 32)
		for i := range ids {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				// retries of the same request under one key, racing each other
				r, err := s.Append(ctx, concReq("idem", key, 0))
				if err == nil {
					ids[i] = r.ID
				}
				errs[i] = err
			}(i)
		}
		// concurrent unrelated appends on the same chain interleave with the retries
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if _, err := s.Append(ctx, concReq("idem", "", 100+i)); err != nil {
					t.Error(err)
				}
			}(i)
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("retry %d: %v", i, err)
			}
			if ids[i] != ids[0] {
				t.Fatalf("round %d: retries got different records %s vs %s", round, ids[i], ids[0])
			}
		}
		// reusing the key for a different request must be refused, never silently dropped
		var ce *ConflictError
		if _, err := s.Append(ctx, concReq("idem", key, 1)); !errors.As(err, &ce) {
			t.Fatalf("round %d: different payload under a used key: %v, want ConflictError", round, err)
		}
		var n int
		_ = s.Pool.QueryRow(ctx, `SELECT count(*) FROM records WHERE chain='idem' AND idempotency_key=$1`, key).Scan(&n)
		if n != 1 {
			t.Fatalf("round %d: %d records for one idempotency key", round, n)
		}
	}
	if res, _ := s.Verify(ctx, "idem"); !res.OK || res.Length != 5*(1+8) {
		t.Fatalf("verify: %+v", res)
	}
}
