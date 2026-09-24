// Package store is the Postgres-backed append-only, hash-chained record store.
package store

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/canon"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Actor is one hop of the delegation chain.
type Actor struct {
	Kind         string `json:"kind"`
	ID           string `json:"id"`
	Model        string `json:"model,omitempty"`
	ModelVersion string `json:"model_version,omitempty"`
}

// AppendRequest is the body of POST /v1/records.
type AppendRequest struct {
	Chain         string          `json:"chain"`
	Type          string          `json:"type"`
	GoalID        string          `json:"goal_id,omitempty"`
	ActorChain    []Actor         `json:"actor_chain"`
	PolicyVersion string          `json:"policy_version,omitempty"`
	Payload       json.RawMessage `json:"payload"`
	// IdempotencyKey, when set, makes a retried append with the same (chain, key) a no-op
	// that returns the original record instead of creating a new one. Optional; additive.
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	// DataSubject, when set (and ledgerd has a data key store), makes the API encrypt the payload
	// with that subject's data key before appending (see internal/keys envelope). It is never
	// stored or hashed itself. Optional; additive.
	DataSubject string `json:"data_subject,omitempty"`
}

// Record is a stored record.
type Record struct {
	ID             string          `json:"id"`
	Chain          string          `json:"chain"`
	Seq            int64           `json:"seq"`
	Type           string          `json:"type"`
	GoalID         string          `json:"goal_id,omitempty"`
	ActorChain     json.RawMessage `json:"actor_chain"`
	PolicyVersion  string          `json:"policy_version,omitempty"`
	Payload        json.RawMessage `json:"payload"`
	CreatedAt      time.Time       `json:"created_at"`
	PrevHash       string          `json:"prev_hash"`
	Hash           string          `json:"hash"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
}

// Input limits. Names are indexed (a btree entry holds at most ~2.7kB), so they are capped well
// below that; the caps are generous for real chain/goal/key names.
const (
	MaxNameLen = 512 // chain, goal_id, idempotency_key, actor id/model/model_version
	MaxTypeLen = 256 // type, policy_version
	MaxActors  = 64  // delegation hops in actor_chain
)

// ValidationError marks a client error.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

// Validate enforces the contract rules for an append request.
func (r *AppendRequest) Validate() error {
	if strings.TrimSpace(r.Chain) == "" {
		return &ValidationError{"chain is required"}
	}
	if strings.ContainsFunc(r.Chain, func(c rune) bool { return c < 0x20 || c == 0x7f }) {
		return &ValidationError{"chain must not contain control characters"}
	}
	if strings.TrimSpace(r.Type) == "" {
		return &ValidationError{"type is required"}
	}
	for _, f := range []struct {
		name, v string
		max     int
	}{{"chain", r.Chain, MaxNameLen}, {"type", r.Type, MaxTypeLen}, {"goal_id", r.GoalID, MaxNameLen},
		{"policy_version", r.PolicyVersion, MaxTypeLen}, {"idempotency_key", r.IdempotencyKey, MaxNameLen}} {
		if err := checkText(f.name, f.v, f.max); err != nil {
			return err
		}
	}
	if len(r.ActorChain) == 0 {
		return &ValidationError{"actor_chain must be non-empty"}
	}
	if len(r.ActorChain) > MaxActors {
		return &ValidationError{fmt.Sprintf("actor_chain has more than %d entries", MaxActors)}
	}
	if r.ActorChain[0].Kind != "human" {
		return &ValidationError{"actor_chain[0].kind must be \"human\" (originating human is never dropped)"}
	}
	for i, a := range r.ActorChain {
		switch a.Kind {
		case "human", "agent", "service":
		default:
			return &ValidationError{fmt.Sprintf("actor_chain[%d].kind must be human|agent|service", i)}
		}
		if a.ID == "" {
			return &ValidationError{fmt.Sprintf("actor_chain[%d].id is required", i)}
		}
		for k, v := range map[string]string{"id": a.ID, "model": a.Model, "model_version": a.ModelVersion} {
			if err := checkText(fmt.Sprintf("actor_chain[%d].%s", i, k), v, MaxNameLen); err != nil {
				return err
			}
		}
	}
	if len(r.Payload) == 0 || string(r.Payload) == "null" {
		r.Payload = json.RawMessage(`{}`)
	}
	pl, err := canon.Normalize(r.Payload)
	if err != nil {
		return &ValidationError{"payload must be valid JSON"}
	}
	if err := CheckDuplicateKeys(r.Payload); err != nil {
		return &ValidationError{"payload: " + err.Error()}
	}
	if _, ok := pl.(map[string]any); !ok {
		return &ValidationError{"payload must be a JSON object"}
	}
	return nil
}

// checkText rejects strings Postgres text columns cannot hold (NUL) and oversized names.
func checkText(field, v string, max int) error {
	if len(v) > max {
		return &ValidationError{fmt.Sprintf("%s is longer than %d bytes", field, max)}
	}
	if strings.IndexByte(v, 0) >= 0 {
		return &ValidationError{field + " must not contain NUL characters"}
	}
	return nil
}

// HashBody is the canonical object that is hashed (the record without hash/prev_hash).
func HashBody(r *Record) (map[string]any, error) {
	ac, err := canon.Normalize(r.ActorChain)
	if err != nil {
		return nil, fmt.Errorf("actor_chain: %w", err)
	}
	pl, err := canon.Normalize(r.Payload)
	if err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	return map[string]any{
		"id":             r.ID,
		"chain":          r.Chain,
		"seq":            r.Seq,
		"type":           r.Type,
		"goal_id":        r.GoalID,
		"actor_chain":    ac,
		"policy_version": r.PolicyVersion,
		"payload":        pl,
		"created_at":     r.CreatedAt.UTC().Format(time.RFC3339Nano),
	}, nil
}

// ComputeHash returns the record hash given its prev_hash.
func ComputeHash(r *Record) (string, error) {
	b, err := HashBody(r)
	if err != nil {
		return "", err
	}
	return canon.Hash(r.PrevHash, b)
}

// Store wraps a pgx pool.
type Store struct{ Pool *pgxpool.Pool }

// Open connects and runs migrations.
func Open(ctx context.Context, url string) (*Store, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	s := &Store{Pool: pool}
	if err := s.Migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() { s.Pool.Close() }

// Migrate applies embedded migrations in lexical order, once each.
func (s *Store) Migrate(ctx context.Context) error {
	// The advisory lock is session-scoped: take it, migrate and release it on ONE connection.
	// (Through the pool, the unlock could run on a different connection than the lock and
	// leave it held by an idle pooled connection, blocking every later migration.)
	conn, err := s.Pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(8410001)`); err != nil {
		return err
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock(8410001)`) //nolint:errcheck
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, n := range names {
		var exists bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE name=$1)`, n).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		sqlb, _ := migrationFS.ReadFile("migrations/" + n)
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sqlb)); err != nil {
			tx.Rollback(ctx) //nolint:errcheck
			return fmt.Errorf("migration %s: %w", n, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(name) VALUES ($1)`, n); err != nil {
			tx.Rollback(ctx) //nolint:errcheck
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Append validates and appends a record to its chain. Appends to a chain are serialized
// with a transaction-scoped advisory lock so seq/prev_hash are always consistent.
func (s *Store) Append(ctx context.Context, req AppendRequest) (*Record, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	acRaw, _ := json.Marshal(req.ActorChain)
	acCanon, err := canon.CanonicalBytes(acRaw)
	if err != nil {
		return nil, err
	}
	plCanon, err := canon.CanonicalBytes(req.Payload)
	if err != nil {
		return nil, err
	}
	// Round trips are pipelined (ledger bench): one batch takes the per-chain lock, creates the
	// chain if needed, looks up the idempotency key and reads the head; a second batch writes the
	// record, advances the head and upserts the domain rows. Semantics are unchanged: appends
	// to a chain are serialized by the transaction-scoped advisory lock + the head row lock.
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	b1 := &pgx.Batch{}
	b1.Queue(`SELECT pg_advisory_xact_lock(8410, hashtext($1))`, req.Chain)
	b1.Queue(`INSERT INTO chains(name) VALUES ($1) ON CONFLICT DO NOTHING`, req.Chain)
	if req.IdempotencyKey != "" {
		b1.Queue(selectColsWithKey+` WHERE chain=$1 AND idempotency_key=$2`, req.Chain, req.IdempotencyKey)
	}
	b1.Queue(`SELECT head_seq, head_hash FROM chains WHERE name=$1 FOR UPDATE`, req.Chain)
	br := tx.SendBatch(ctx, b1)
	if _, err := br.Exec(); err != nil {
		br.Close()
		return nil, err
	}
	if _, err := br.Exec(); err != nil {
		br.Close()
		return nil, err
	}
	var existing []Record
	if req.IdempotencyKey != "" {
		rows, err := br.Query()
		if err != nil {
			br.Close()
			return nil, err
		}
		if existing, err = scanRecordsWithKey(rows); err != nil {
			br.Close()
			return nil, err
		}
	}
	var headSeq int64
	var headHash string
	if err := br.QueryRow().Scan(&headSeq, &headHash); err != nil {
		br.Close()
		return nil, err
	}
	if err := br.Close(); err != nil {
		return nil, err
	}
	if len(existing) > 0 {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		if !sameRequest(&existing[0], &req, acCanon, plCanon) {
			return nil, &ConflictError{"idempotency_key already used on this chain for a different record (type, goal_id, actor_chain, policy_version or payload differ)"}
		}
		return &existing[0], nil
	}
	rec := &Record{
		ID:             newUUID(),
		Chain:          req.Chain,
		Seq:            headSeq + 1,
		Type:           req.Type,
		GoalID:         req.GoalID,
		ActorChain:     acCanon,
		PolicyVersion:  req.PolicyVersion,
		Payload:        plCanon,
		CreatedAt:      time.Now().UTC().Truncate(time.Microsecond),
		PrevHash:       headHash,
		IdempotencyKey: req.IdempotencyKey,
	}
	if rec.Hash, err = ComputeHash(rec); err != nil {
		return nil, err
	}
	b2 := &pgx.Batch{}
	b2.Queue(`INSERT INTO records(id,chain,seq,type,goal_id,actor_chain,policy_version,payload,created_at,prev_hash,hash,idempotency_key)
		VALUES ($1,$2,$3,$4,NULLIF($5,''),$6,NULLIF($7,''),$8,$9,$10,$11,NULLIF($12,''))`,
		rec.ID, rec.Chain, rec.Seq, rec.Type, rec.GoalID, string(rec.ActorChain), rec.PolicyVersion, string(rec.Payload), rec.CreatedAt, rec.PrevHash, rec.Hash, rec.IdempotencyKey)
	b2.Queue(`UPDATE chains SET head_seq=$2, head_hash=$3, updated_at=now() WHERE name=$1`, rec.Chain, rec.Seq, rec.Hash)
	// Projections into the domain tables (one statement for all actors).
	ids, kinds, models, versions := make([]string, len(req.ActorChain)), make([]string, len(req.ActorChain)), make([]string, len(req.ActorChain)), make([]string, len(req.ActorChain))
	for i, a := range req.ActorChain {
		ids[i], kinds[i], models[i], versions[i] = a.ID, a.Kind, a.Model, a.ModelVersion
	}
	b2.Queue(`INSERT INTO operators(id,kind,model,model_version)
		SELECT DISTINCT ON (id) id, kind, NULLIF(model,''), NULLIF(mv,'') FROM unnest($1::text[], $2::text[], $3::text[], $4::text[]) AS a(id,kind,model,mv)
		ON CONFLICT (id) DO NOTHING`, ids, kinds, models, versions)
	if rec.GoalID != "" {
		// DO NOTHING (not DO UPDATE SET updated_at): rewriting the goal row on every append made
		// concurrent writers on different chains of the same goal queue on its row lock.
		// goals.updated_at is maintained by the projector.
		b2.Queue(`INSERT INTO goals(id, originating_human_id, first_record_id) VALUES ($1,$2,$3)
			ON CONFLICT (id) DO NOTHING`, rec.GoalID, req.ActorChain[0].ID, rec.ID)
	}
	if err := tx.SendBatch(ctx, b2).Close(); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return rec, nil
}

// Query filters for List.
type Query struct {
	Chain    string
	GoalID   string
	AfterSeq int64
	Limit    int
}

const selectCols = `SELECT id::text, chain, seq, type, COALESCE(goal_id,''), actor_chain::text, COALESCE(policy_version,''), payload::text, created_at, prev_hash, hash FROM records`

const selectColsWithKey = `SELECT id::text, chain, seq, type, COALESCE(goal_id,''), actor_chain::text, COALESCE(policy_version,''), payload::text, created_at, prev_hash, hash, COALESCE(idempotency_key,'') FROM records`

func scanRecords(rows pgx.Rows) ([]Record, error) {
	defer rows.Close()
	out := []Record{}
	for rows.Next() {
		var r Record
		var ac, pl string
		if err := rows.Scan(&r.ID, &r.Chain, &r.Seq, &r.Type, &r.GoalID, &ac, &r.PolicyVersion, &pl, &r.CreatedAt, &r.PrevHash, &r.Hash); err != nil {
			return nil, err
		}
		r.CreatedAt = r.CreatedAt.UTC()
		r.ActorChain, r.Payload = json.RawMessage(ac), json.RawMessage(pl)
		out = append(out, r)
	}
	return out, rows.Err()
}

// scanRecordsWithKey scans rows selected with selectColsWithKey (adds idempotency_key).
func scanRecordsWithKey(rows pgx.Rows) ([]Record, error) {
	defer rows.Close()
	out := []Record{}
	for rows.Next() {
		var r Record
		var ac, pl string
		if err := rows.Scan(&r.ID, &r.Chain, &r.Seq, &r.Type, &r.GoalID, &ac, &r.PolicyVersion, &pl, &r.CreatedAt, &r.PrevHash, &r.Hash, &r.IdempotencyKey); err != nil {
			return nil, err
		}
		r.CreatedAt = r.CreatedAt.UTC()
		r.ActorChain, r.Payload = json.RawMessage(ac), json.RawMessage(pl)
		out = append(out, r)
	}
	return out, rows.Err()
}

// List returns records matching q.
func (s *Store) List(ctx context.Context, q Query) ([]Record, error) {
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 100
	}
	var conds []string
	var args []any
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
	sqlq := selectCols
	if len(conds) > 0 {
		sqlq += " WHERE " + strings.Join(conds, " AND ")
	}
	args = append(args, q.Limit)
	sqlq += fmt.Sprintf(" ORDER BY created_at, chain, seq LIMIT $%d", len(args))
	rows, err := s.Pool.Query(ctx, sqlq, args...)
	if err != nil {
		return nil, err
	}
	return scanRecords(rows)
}

// Replay returns all records for a goal across chains, in time order.
func (s *Store) Replay(ctx context.Context, goalID string) ([]Record, error) {
	rows, err := s.Pool.Query(ctx, selectCols+` WHERE goal_id=$1 ORDER BY created_at, chain, seq`, goalID)
	if err != nil {
		return nil, err
	}
	return scanRecords(rows)
}

// ChainRecords returns an entire chain in seq order.
func (s *Store) ChainRecords(ctx context.Context, chain string) ([]Record, error) {
	rows, err := s.Pool.Query(ctx, selectCols+` WHERE chain=$1 ORDER BY seq`, chain)
	if err != nil {
		return nil, err
	}
	return scanRecords(rows)
}

// Chains lists chain names.
func (s *Store) Chains(ctx context.Context) ([]string, error) {
	rows, err := s.Pool.Query(ctx, `SELECT name FROM chains ORDER BY name`)
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

// VerifyResult is the response of GET /v1/chains/{chain}/verify.
type VerifyResult struct {
	Chain    string `json:"chain"`
	OK       bool   `json:"ok"`
	Length   int    `json:"length"`
	Head     string `json:"head"`
	BrokenAt *int64 `json:"broken_at"`
	Reason   string `json:"reason,omitempty"`
}

// VerifyRecords checks seq continuity, prev_hash linkage, and each stored hash.
func VerifyRecords(chain string, recs []Record) VerifyResult {
	res := VerifyResult{Chain: chain, OK: true, Length: len(recs)}
	prev := ""
	for i := range recs {
		r := &recs[i]
		fail := func(reason string) VerifyResult {
			seq := r.Seq
			res.OK, res.BrokenAt, res.Reason = false, &seq, reason
			return res
		}
		if r.Seq != int64(i+1) {
			return fail(fmt.Sprintf("expected seq %d, found %d", i+1, r.Seq))
		}
		if r.PrevHash != prev {
			return fail("prev_hash does not match previous record hash")
		}
		h, err := ComputeHash(r)
		if err != nil {
			return fail("undecodable record: " + err.Error())
		}
		if h != r.Hash {
			return fail("stored hash does not match recomputed hash (record content altered)")
		}
		prev = r.Hash
		res.Head = r.Hash
	}
	return res
}

// Verify verifies a whole chain, also checking the chains.head pointer. It streams the chain
// in pages with parallel hashing (see VerifyStream) so memory stays constant for long chains.
func (s *Store) Verify(ctx context.Context, chain string) (VerifyResult, error) {
	return s.VerifyStream(ctx, chain, VerifyBatchSize)
}

// Head returns the current head of a chain (seq 0, "" if empty/unknown).
func (s *Store) Head(ctx context.Context, chain string) (int64, string, error) {
	var seq int64
	var h string
	err := s.Pool.QueryRow(ctx, `SELECT head_seq, head_hash FROM chains WHERE name=$1`, chain).Scan(&seq, &h)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, "", nil
	}
	return seq, h, err
}

// SaveAnchor persists an anchor row.
func (s *Store) SaveAnchor(ctx context.Context, chain string, seq int64, head, sig, pub string) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO anchors(chain,seq,head,signature,public_key) VALUES ($1,$2,$3,$4,$5)`, chain, seq, head, sig, pub)
	return err
}
