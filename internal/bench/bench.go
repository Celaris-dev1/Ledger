// Package bench measures Ledger's hot paths against a real Postgres: concurrent append
// throughput across many chains, and verification speed on long chains.
package bench

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Celaris-dev1/Ledger/internal/canon"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

// AppendResult summarises an append run.
type AppendResult struct {
	Writers    int           `json:"writers"`
	Chains     int           `json:"chains"`
	Records    int           `json:"records"`
	Errors     int64         `json:"errors"`
	Elapsed    time.Duration `json:"elapsed_ns"`
	PerSecond  float64       `json:"records_per_second"`
	P50        time.Duration `json:"p50_ns"`
	P99        time.Duration `json:"p99_ns"`
	AllIntact  bool          `json:"all_chains_intact"`
	VerifiedIn time.Duration `json:"verify_all_ns"`
}

func (r AppendResult) String() string {
	return fmt.Sprintf("append: %d records, %d writers, %d chains in %s = %.0f rec/s (p50 %s, p99 %s, errors %d); verify all chains %s intact=%v",
		r.Records, r.Writers, r.Chains, r.Elapsed.Round(time.Millisecond), r.PerSecond, r.P50.Round(10*time.Microsecond),
		r.P99.Round(10*time.Microsecond), r.Errors, r.VerifiedIn.Round(time.Millisecond), r.AllIntact)
}

// Append runs `records` appends from `writers` goroutines spread over `chains` chains, with a
// realistic payload (~payloadBytes) and a 2-hop actor chain.
func Append(ctx context.Context, st *store.Store, writers, chains, records, payloadBytes int) (AppendResult, error) {
	res := AppendResult{Writers: writers, Chains: chains, Records: records}
	pad := strings.Repeat("x", payloadBytes)
	lat := make([]time.Duration, records)
	var next int64 = -1
	var errs int64
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for {
				i := atomic.AddInt64(&next, 1)
				if i >= int64(records) {
					return
				}
				pl, _ := json.Marshal(map[string]any{"i": i, "writer": w, "pad": pad})
				req := store.AppendRequest{Chain: fmt.Sprintf("bench-%03d", i%int64(chains)), Type: "bench.run.scored",
					GoalID: fmt.Sprintf("goal-%d", i%97), PolicyVersion: "p1",
					ActorChain: []store.Actor{{Kind: "human", ID: "bench-human"}, {Kind: "agent", ID: fmt.Sprintf("agent-%d", w%8), Model: "m", ModelVersion: "1"}},
					Payload:    pl}
				t0 := time.Now()
				if _, err := st.Append(ctx, req); err != nil {
					atomic.AddInt64(&errs, 1)
				}
				lat[i] = time.Since(t0)
			}
		}(w)
	}
	wg.Wait()
	res.Elapsed = time.Since(start)
	res.Errors = errs
	res.PerSecond = float64(records) / res.Elapsed.Seconds()
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	if records > 0 {
		res.P50, res.P99 = lat[records/2], lat[records*99/100]
	}
	t0 := time.Now()
	res.AllIntact = true
	for c := 0; c < chains; c++ {
		v, err := st.Verify(ctx, fmt.Sprintf("bench-%03d", c))
		if err != nil {
			return res, err
		}
		res.AllIntact = res.AllIntact && v.OK
	}
	res.VerifiedIn = time.Since(t0)
	return res, nil
}

// VerifyResult summarises a long-chain verification run.
type VerifyResult struct {
	Records       int           `json:"records"`
	LoadElapsed   time.Duration `json:"bulk_load_ns"`
	StreamElapsed time.Duration `json:"verify_streaming_ns"`
	StreamPerSec  float64       `json:"verify_streaming_records_per_second"`
	MemElapsed    time.Duration `json:"verify_in_memory_ns,omitempty"`
	MemPerSec     float64       `json:"verify_in_memory_records_per_second,omitempty"`
	OK            bool          `json:"ok"`
}

func (r VerifyResult) String() string {
	s := fmt.Sprintf("verify: %d-record chain (bulk-loaded in %s): streaming+parallel %s = %.0f rec/s",
		r.Records, r.LoadElapsed.Round(time.Millisecond), r.StreamElapsed.Round(time.Millisecond), r.StreamPerSec)
	if r.MemElapsed > 0 {
		s += fmt.Sprintf("; load-all+sequential (previous implementation) %s = %.0f rec/s", r.MemElapsed.Round(time.Millisecond), r.MemPerSec)
	}
	return s + fmt.Sprintf(" ok=%v", r.OK)
}

// BulkLoad writes a valid n-record chain with COPY (the append path would take far longer
// for 1M records; the resulting rows are identical in shape).
func BulkLoad(ctx context.Context, st *store.Store, chain string, n int) error {
	const batch = 20000
	prev := ""
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ac := json.RawMessage(`[{"id":"bench-human","kind":"human"},{"id":"agent-1","kind":"agent","model":"m","model_version":"1"}]`)
	if _, err := st.Pool.Exec(ctx, `INSERT INTO chains(name) VALUES ($1) ON CONFLICT DO NOTHING`, chain); err != nil {
		return err
	}
	for lo := 0; lo < n; lo += batch {
		hi := min(lo+batch, n)
		rows := make([][]any, 0, hi-lo)
		for i := lo; i < hi; i++ {
			pl, _ := canon.CanonicalBytes([]byte(fmt.Sprintf(`{"i":%d,"tool":"http.get","status":"committed","url":"https://example.com/%d"}`, i, i)))
			r := store.Record{ID: uuid(), Chain: chain, Seq: int64(i + 1), Type: "harbour.effect.result", GoalID: fmt.Sprintf("g-%d", i/1000),
				ActorChain: ac, Payload: pl, CreatedAt: t0.Add(time.Duration(i) * time.Millisecond), PrevHash: prev}
			h, err := store.ComputeHash(&r)
			if err != nil {
				return err
			}
			r.Hash, prev = h, h
			rows = append(rows, []any{r.ID, r.Chain, r.Seq, r.Type, r.GoalID, string(r.ActorChain), string(r.Payload), r.CreatedAt, r.PrevHash, r.Hash})
		}
		if _, err := st.Pool.CopyFrom(ctx, pgx.Identifier{"records"},
			[]string{"id", "chain", "seq", "type", "goal_id", "actor_chain", "payload", "created_at", "prev_hash", "hash"}, pgx.CopyFromRows(rows)); err != nil {
			return err
		}
	}
	_, err := st.Pool.Exec(ctx, `UPDATE chains SET head_seq=$2, head_hash=$3 WHERE name=$1`, chain, n, prev)
	return err
}

// Verify bulk-loads an n-record chain and times streaming verification (and, if withMem,
// the previous load-everything + sequential implementation for comparison).
func Verify(ctx context.Context, st *store.Store, n int, withMem bool) (VerifyResult, error) {
	res := VerifyResult{Records: n}
	chain := "bench-long"
	t0 := time.Now()
	if err := BulkLoad(ctx, st, chain, n); err != nil {
		return res, err
	}
	res.LoadElapsed = time.Since(t0)
	t0 = time.Now()
	v, err := st.Verify(ctx, chain)
	if err != nil {
		return res, err
	}
	res.StreamElapsed = time.Since(t0)
	res.StreamPerSec = float64(n) / res.StreamElapsed.Seconds()
	res.OK = v.OK && v.Length == n
	if withMem {
		t0 = time.Now()
		recs, err := st.ChainRecords(ctx, chain)
		if err != nil {
			return res, err
		}
		mv := store.VerifyRecords(chain, recs)
		res.MemElapsed = time.Since(t0)
		res.MemPerSec = float64(n) / res.MemElapsed.Seconds()
		res.OK = res.OK && mv.OK
	}
	return res, nil
}

func uuid() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Scratch opens a store in a throwaway schema of baseURL; cleanup drops it.
func Scratch(ctx context.Context, baseURL string) (*store.Store, func(), error) {
	var b [4]byte
	_, _ = rand.Read(b[:])
	schema := "ledger_bench_" + hex.EncodeToString(b[:])
	admin, err := pgx.Connect(ctx, baseURL)
	if err != nil {
		return nil, nil, err
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close(ctx)
		return nil, nil, err
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, nil, err
	}
	q := u.Query()
	q.Set("search_path", schema)
	if q.Get("pool_max_conns") == "" {
		q.Set("pool_max_conns", "32")
	}
	u.RawQuery = q.Encode()
	st, err := store.Open(ctx, u.String())
	if err != nil {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
		admin.Close(ctx)
		return nil, nil, err
	}
	return st, func() {
		st.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		admin.Close(context.Background())
	}, nil
}
