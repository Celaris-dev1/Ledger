package store

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// VerifyBatchSize is the page size of streaming verification.
const VerifyBatchSize = 5000

// ChainBatch returns up to limit records of a chain with seq > afterSeq, in seq order
// (keyset pagination over the (chain, seq) unique index).
func (s *Store) ChainBatch(ctx context.Context, chain string, afterSeq int64, limit int) ([]Record, error) {
	rows, err := s.Pool.Query(ctx, selectCols+` WHERE chain=$1 AND seq>$2 ORDER BY seq LIMIT $3`, chain, afterSeq, limit)
	if err != nil {
		return nil, err
	}
	return scanRecords(rows)
}

// hashAll recomputes record hashes in parallel (each hash depends only on the record and
// its stored prev_hash; linkage is checked sequentially afterwards).
func hashAll(recs []Record, workers int) ([]string, []error) {
	hs := make([]string, len(recs))
	errs := make([]error, len(recs))
	if workers <= 1 || len(recs) < 256 {
		for i := range recs {
			hs[i], errs[i] = ComputeHash(&recs[i])
		}
		return hs, errs
	}
	var wg sync.WaitGroup
	chunk := (len(recs) + workers - 1) / workers
	for w := 0; w < workers; w++ {
		lo, hi := w*chunk, (w+1)*chunk
		if hi > len(recs) {
			hi = len(recs)
		}
		if lo >= hi {
			break
		}
		wg.Add(1)
		go func(lo, hi int) {
			defer wg.Done()
			for i := lo; i < hi; i++ {
				hs[i], errs[i] = ComputeHash(&recs[i])
			}
		}(lo, hi)
	}
	wg.Wait()
	return hs, errs
}

// Verifier incrementally verifies a chain fed in seq order, batch by batch. Its verdicts are
// identical to VerifyRecords over the concatenation of all batches.
type Verifier struct {
	Res     VerifyResult
	Workers int
	prev    string
	n       int64
}

// NewVerifier starts verifying chain.
func NewVerifier(chain string) *Verifier {
	return &Verifier{Res: VerifyResult{Chain: chain, OK: true}, Workers: runtime.GOMAXPROCS(0)}
}

// Feed verifies the next batch; it returns false once the chain is found broken.
func (v *Verifier) Feed(recs []Record) bool {
	if !v.Res.OK {
		return false
	}
	hs, errs := hashAll(recs, v.Workers)
	for i := range recs {
		r := &recs[i]
		v.n++
		v.Res.Length = int(v.n)
		fail := func(reason string) bool {
			seq := r.Seq
			v.Res.OK, v.Res.BrokenAt, v.Res.Reason = false, &seq, reason
			return false
		}
		if r.Seq != v.n {
			return fail(fmt.Sprintf("expected seq %d, found %d", v.n, r.Seq))
		}
		if r.PrevHash != v.prev {
			return fail("prev_hash does not match previous record hash")
		}
		if errs[i] != nil {
			return fail("undecodable record: " + errs[i].Error())
		}
		if hs[i] != r.Hash {
			return fail("stored hash does not match recomputed hash (record content altered)")
		}
		v.prev = r.Hash
		v.Res.Head = r.Hash
	}
	return true
}

// VerifyStream verifies a chain in pages of batch records with parallel hashing, using
// constant memory (the 1M-record path), and checks the chains.head pointer like Verify.
func (s *Store) VerifyStream(ctx context.Context, chain string, batch int) (VerifyResult, error) {
	if batch <= 0 {
		batch = VerifyBatchSize
	}
	v := NewVerifier(chain)
	// Prefetch: the next page is read from Postgres while the current one is hashed.
	type page struct {
		recs []Record
		err  error
	}
	pages := make(chan page, 2)
	fctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		defer close(pages)
		var after int64
		for {
			recs, err := s.ChainBatch(fctx, chain, after, batch)
			select {
			case pages <- page{recs, err}:
			case <-fctx.Done():
				return
			}
			if err != nil || len(recs) < batch {
				return
			}
			after = recs[len(recs)-1].Seq
		}
	}()
	for pg := range pages {
		if pg.err != nil {
			return VerifyResult{}, pg.err
		}
		recs := pg.recs
		if len(recs) == 0 {
			break
		}
		// a gap (missing seq) must be reported at the right place even across pages
		if !v.Feed(recs) {
			// Length counts records examined so far; report the full length like VerifyRecords
			var total int
			if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM records WHERE chain=$1`, chain).Scan(&total); err == nil {
				v.Res.Length = total
			}
			return v.Res, nil
		}
	}
	res := v.Res
	var headSeq int64
	var headHash string
	err := s.Pool.QueryRow(ctx, `SELECT head_seq, head_hash FROM chains WHERE name=$1`, chain).Scan(&headSeq, &headHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return res, err
	}
	if err == nil && (headSeq != int64(res.Length) || headHash != res.Head) {
		b := int64(res.Length)
		res.OK, res.BrokenAt, res.Reason = false, &b, "chain head pointer disagrees with records (truncation?)"
	}
	return res, nil
}

// ---- tenant-scoped queries (see migration 0500) ----

// TenantPrefix is the reserved chain-name prefix for tenant t ("" for the default tenant).
func TenantPrefix(t string) string {
	if t == "" || t == DefaultTenant {
		return ""
	}
	return "t/" + t + "/"
}

// DefaultTenant owns every chain without the reserved "t/<tenant>/" prefix.
const DefaultTenant = "default"

// TenantOfChain mirrors the SQL ledger_tenant_of().
func TenantOfChain(chain string) string {
	if strings.HasPrefix(chain, "t/") {
		rest := chain[2:]
		if i := strings.IndexByte(rest, '/'); i > 0 {
			return rest[:i]
		}
	}
	return DefaultTenant
}

// ListTenant is List restricted to one tenant (chain names are physical names).
func (s *Store) ListTenant(ctx context.Context, tenant string, q Query) ([]Record, error) {
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 100
	}
	args := []any{tenant}
	conds := []string{"tenant=$1"}
	if q.Chain != "" {
		args = append(args, q.Chain)
		conds = append(conds, fmt.Sprintf("chain=$%d", len(args)))
	}
	if q.GoalID != "" {
		args = append(args, q.GoalID)
		conds = append(conds, fmt.Sprintf("goal_id=$%d", len(args)))
	}
	if q.AfterSeq > 0 {
		args = append(args, q.AfterSeq)
		conds = append(conds, fmt.Sprintf("seq>$%d", len(args)))
	}
	args = append(args, q.Limit)
	rows, err := s.Pool.Query(ctx, selectCols+" WHERE "+strings.Join(conds, " AND ")+
		fmt.Sprintf(" ORDER BY created_at, chain, seq LIMIT $%d", len(args)), args...)
	if err != nil {
		return nil, err
	}
	return scanRecords(rows)
}

// ReplayTenant is Replay restricted to one tenant.
func (s *Store) ReplayTenant(ctx context.Context, tenant, goalID string) ([]Record, error) {
	rows, err := s.Pool.Query(ctx, selectCols+` WHERE tenant=$1 AND goal_id=$2 ORDER BY created_at, chain, seq`, tenant, goalID)
	if err != nil {
		return nil, err
	}
	return scanRecords(rows)
}

// ChainsTenant lists the physical chain names of one tenant.
func (s *Store) ChainsTenant(ctx context.Context, tenant string) ([]string, error) {
	rows, err := s.Pool.Query(ctx, `SELECT name FROM chains WHERE tenant=$1 ORDER BY name`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// WindowRecords returns records of the given chains with from <= created_at < to (zero times
// are open bounds), in (created_at, chain, seq) order.
func (s *Store) WindowRecords(ctx context.Context, chains []string, from, to time.Time) ([]Record, error) {
	if to.IsZero() {
		to = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	rows, err := s.Pool.Query(ctx, selectCols+` WHERE chain = ANY($1) AND created_at >= $2 AND created_at < $3 ORDER BY created_at, chain, seq`, chains, from, to)
	if err != nil {
		return nil, err
	}
	return scanRecords(rows)
}
