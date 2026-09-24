package projection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PG projects records into the Postgres domain tables.
type PG struct {
	Pool  *pgxpool.Pool
	Batch int // records per transaction (default 500)
}

const lockKey = 200 // pg_advisory_xact_lock(8410, 200) serialises projector transactions

// Stats describes one catch-up run.
type Stats struct {
	Records int            `json:"records"`
	Ops     int            `json:"ops"`
	Groups  int            `json:"groups"`
	Rebuilt bool           `json:"rebuilt"`
	Unknown map[string]int `json:"unmapped_types,omitempty"`
}

func (p *PG) batch() int {
	if p.Batch <= 0 {
		return 500
	}
	return p.Batch
}

// storedVersion returns the projector version the tables were built with (0 = never).
func (p *PG) storedVersion(ctx context.Context) (int, error) {
	var v int
	err := p.Pool.QueryRow(ctx, `SELECT version FROM projection_meta WHERE id=1`).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return v, err
}

// Rebuild deletes all projected rows and cursors, then projects every chain from seq 1.
func (p *PG) Rebuild(ctx context.Context) (Stats, error) {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return Stats{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(8410, $1)`, lockKey); err != nil {
		return Stats{}, err
	}
	// Goals, operators and tools are upserted with every projected column, so they are
	// overwritten rather than deleted (store.Append also inserts goals/operators).
	for _, q := range []string{
		`DELETE FROM approval_decisions`, `DELETE FROM verification_results`, `DELETE FROM approval_requests`,
		`DELETE FROM budget_ledger`, `DELETE FROM identity_facts`, `DELETE FROM memory_items`,
		`DELETE FROM action_attempts`, `DELETE FROM goal_steps`, `DELETE FROM projection_ops`, `DELETE FROM projection_cursors`,
		`UPDATE goals SET title=NULL, status='open'`,
	} {
		if _, err := tx.Exec(ctx, q); err != nil {
			return Stats{}, fmt.Errorf("%s: %w", q, err)
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO projection_meta(id,version,rebuilt_at) VALUES (1,$1,now())
		ON CONFLICT (id) DO UPDATE SET version=EXCLUDED.version, rebuilt_at=now()`, Version); err != nil {
		return Stats{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Stats{}, err
	}
	st, err := p.catchUp(ctx)
	st.Rebuilt = true
	return st, err
}

// CatchUp projects every record not yet projected (per-chain cursors). If the stored
// projection was built by a different projector Version it is rebuilt first.
func (p *PG) CatchUp(ctx context.Context) (Stats, error) {
	v, err := p.storedVersion(ctx)
	if err != nil {
		return Stats{}, err
	}
	if v != Version {
		return p.Rebuild(ctx)
	}
	return p.catchUp(ctx)
}

func (p *PG) catchUp(ctx context.Context) (Stats, error) {
	st := Stats{Unknown: map[string]int{}}
	rows, err := p.Pool.Query(ctx, `SELECT name FROM chains ORDER BY name`)
	if err != nil {
		return st, err
	}
	chains, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return st, err
	}
	for _, c := range chains {
		for {
			n, err := p.step(ctx, c, &st)
			if err != nil {
				return st, fmt.Errorf("project chain %s: %w", c, err)
			}
			if n < p.batch() {
				break
			}
		}
	}
	return st, nil
}

const recCols = `SELECT id::text, chain, seq, type, COALESCE(goal_id,''), actor_chain::text, COALESCE(policy_version,''), payload::text, created_at, prev_hash, hash FROM records`

func scanRecs(rows pgx.Rows) ([]store.Record, error) {
	defer rows.Close()
	var out []store.Record
	for rows.Next() {
		var r store.Record
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

// step projects one batch of one chain in a single transaction (ops + rows + cursor).
func (p *PG) step(ctx context.Context, chain string, st *Stats) (int, error) {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(8410, $1)`, lockKey); err != nil {
		return 0, err
	}
	var cur int64
	err = tx.QueryRow(ctx, `SELECT seq FROM projection_cursors WHERE chain=$1`, chain).Scan(&cur)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, err
	}
	rows, err := tx.Query(ctx, recCols+` WHERE chain=$1 AND seq>$2 ORDER BY seq LIMIT $3`, chain, cur, p.batch())
	if err != nil {
		return 0, err
	}
	recs, err := scanRecs(rows)
	if err != nil {
		return 0, err
	}
	if len(recs) == 0 {
		return 0, nil
	}
	dirty := map[string]bool{}
	for _, r := range recs {
		ops, mapped := Map(r)
		if !mapped {
			st.Unknown[r.Type]++
		}
		for _, o := range ops {
			data, _ := json.Marshal(o)
			if _, err := tx.Exec(ctx, `INSERT INTO projection_ops(op_id,grp,key,data) VALUES ($1,$2,$3,$4) ON CONFLICT (op_id) DO NOTHING`,
				o.ID, o.Group, o.Key, string(data)); err != nil {
				return 0, err
			}
			dirty[o.Group] = true
			st.Ops++
		}
	}
	if err := p.recompute(ctx, tx, dirty); err != nil {
		return 0, err
	}
	last := recs[len(recs)-1].Seq
	if _, err := tx.Exec(ctx, `INSERT INTO projection_cursors(chain,seq) VALUES ($1,$2)
		ON CONFLICT (chain) DO UPDATE SET seq=EXCLUDED.seq, updated_at=now()`, chain, last); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO projection_meta(id,version) VALUES (1,$1) ON CONFLICT (id) DO NOTHING`, Version); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	st.Records += len(recs)
	st.Groups += len(dirty)
	return len(recs), nil
}

func (p *PG) recompute(ctx context.Context, tx pgx.Tx, dirty map[string]bool) error {
	groups := make([]string, 0, len(dirty))
	for g := range dirty {
		groups = append(groups, g)
	}
	rank := map[string]int{}
	for i, k := range GroupOrder {
		rank[k] = i
	}
	sort.Slice(groups, func(i, j int) bool {
		ri, rj := rank[groupKind(groups[i])], rank[groupKind(groups[j])]
		if ri != rj {
			return ri < rj
		}
		return groups[i] < groups[j]
	})
	for _, g := range groups {
		rows, err := tx.Query(ctx, `SELECT data::text FROM projection_ops WHERE grp=$1`, g)
		if err != nil {
			return err
		}
		datas, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		ops := make([]Op, 0, len(datas))
		for _, d := range datas {
			var o Op
			dec := json.NewDecoder(strings.NewReader(d))
			dec.UseNumber()
			if err := dec.Decode(&o); err != nil {
				return err
			}
			ops = append(ops, o)
		}
		if err := writeGroup(ctx, tx, g, ops); err != nil {
			return fmt.Errorf("group %s: %w", g, err)
		}
	}
	return nil
}

func nz(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func js(r json.RawMessage) any {
	if len(r) == 0 {
		return nil
	}
	return string(r)
}

func opTime(ops []Op, recordID string) any {
	for _, o := range ops {
		if o.RecordID == recordID {
			if t, err := time.Parse(time.RFC3339Nano, o.At); err == nil {
				return t
			}
		}
	}
	return nil
}

func writeGroup(ctx context.Context, tx pgx.Tx, g string, ops []Op) error {
	r := Fold(g, ops)
	var err error
	exec := func(q string, args ...any) {
		if err == nil {
			_, err = tx.Exec(ctx, q, args...)
		}
	}
	for _, o := range r.Operators {
		exec(`INSERT INTO operators(id,kind,model,model_version) VALUES ($1,$2,$3,$4)
			ON CONFLICT (id) DO UPDATE SET kind=EXCLUDED.kind, model=EXCLUDED.model, model_version=EXCLUDED.model_version`,
			o.ID, o.Kind, nz(o.Model), nz(o.ModelVersion))
	}
	for _, t := range r.Tools {
		exec(`INSERT INTO tools(id,name,version,description) VALUES ($1,$2,$3,$4)
			ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, version=EXCLUDED.version, description=EXCLUDED.description`,
			t.ID, t.Name, nz(t.Version), nz(t.Description))
	}
	for _, x := range r.Goals {
		exec(`INSERT INTO goals(id,title,originating_human_id,status,first_record_id) VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (id) DO UPDATE SET title=EXCLUDED.title, originating_human_id=EXCLUDED.originating_human_id,
			status=EXCLUDED.status, first_record_id=EXCLUDED.first_record_id, updated_at=now()`,
			x.ID, nz(x.Title), nz(x.OriginatingHumanID), x.Status, nz(x.FirstRecordID))
	}
	for _, s := range r.Steps {
		exec(`INSERT INTO goal_steps(id,goal_id,step_no,description,status,record_id) VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (id) DO UPDATE SET description=EXCLUDED.description, status=EXCLUDED.status, record_id=EXCLUDED.record_id`,
			s.ID, s.GoalID, s.StepNo, nz(s.Description), s.Status, nz(s.RecordID))
	}
	for _, a := range r.Attempts {
		exec(`INSERT INTO action_attempts(id,attempt_key,goal_id,step_id,tool_id,action_hash,arguments,outcome,policy_version,record_id,result_record_id,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,COALESCE($12::timestamptz, now()))
			ON CONFLICT (id) DO UPDATE SET goal_id=EXCLUDED.goal_id, step_id=EXCLUDED.step_id, tool_id=EXCLUDED.tool_id,
			action_hash=EXCLUDED.action_hash, arguments=EXCLUDED.arguments, outcome=EXCLUDED.outcome, policy_version=EXCLUDED.policy_version,
			record_id=EXCLUDED.record_id, result_record_id=EXCLUDED.result_record_id, created_at=EXCLUDED.created_at`,
			a.ID, a.AttemptKey, nz(a.GoalID), nz(a.StepID), nz(a.ToolID), a.ActionHash, js(a.Arguments), nz(a.Outcome), nz(a.PolicyVersion),
			nz(a.RecordID), nz(a.ResultRecordID), opTime(ops, a.RecordID))
	}
	if groupKind(g) == "approval" {
		exec(`DELETE FROM approval_decisions WHERE request_key=$1`, strings.TrimPrefix(g, "approval:"))
	}
	for _, a := range r.Approvals {
		exec(`INSERT INTO approval_requests(id,request_key,goal_id,action_hash,requested_by,decided_by,decision,reason,record_id,decision_record_id,requested_at,decided_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,COALESCE($11::timestamptz, now()),$12)
			ON CONFLICT (id) DO UPDATE SET goal_id=EXCLUDED.goal_id, action_hash=EXCLUDED.action_hash, requested_by=EXCLUDED.requested_by,
			decided_by=EXCLUDED.decided_by, decision=EXCLUDED.decision, reason=EXCLUDED.reason, record_id=EXCLUDED.record_id,
			decision_record_id=EXCLUDED.decision_record_id, requested_at=EXCLUDED.requested_at, decided_at=EXCLUDED.decided_at`,
			a.ID, a.RequestKey, nz(a.GoalID), a.ActionHash, nz(a.RequestedBy), nz(a.DecidedBy), nz(a.Decision), nz(a.Reason),
			a.RecordID, nz(a.DecisionRecordID), opTime(ops, a.RecordID), opTime(ops, a.DecisionRecordID))
	}
	for _, d := range r.Decisions {
		exec(`INSERT INTO approval_decisions(id,request_key,goal_id,action_hash,decision,decided_by,reason,matched,record_id,decided_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			d.ID, d.RequestKey, nz(d.GoalID), d.ActionHash, d.Decision, nz(d.DecidedBy), nz(d.Reason), d.Matched, d.RecordID, opTime(ops, d.RecordID))
	}
	if groupKind(g) == "budget" {
		exec(`DELETE FROM budget_ledger WHERE grp=$1`, g)
	}
	for _, b := range r.Budget {
		exec(`INSERT INTO budget_ledger(id,grp,position,goal_id,operator_id,resource,entry_kind,delta,balance,overspent,record_id,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,COALESCE($12::timestamptz, now()))`,
			b.ID, b.Group, b.Position, nz(b.GoalID), nz(b.OperatorID), b.Resource, b.EntryKind, b.Delta, b.Balance, b.Overspent, b.RecordID, opTime(ops, b.RecordID))
	}
	for _, v := range r.Verifications {
		exec(`INSERT INTO verification_results(id,action_attempt_id,goal_id,verifier,passed,evidence,record_id,created_at)
			VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,COALESCE($8::timestamptz, now())) ON CONFLICT (id) DO NOTHING`,
			v.ID, nz(v.AttemptID), nz(v.GoalID), v.Verifier, v.Passed, js(v.Evidence), v.RecordID, opTime(ops, v.RecordID))
	}
	for _, i := range r.Identity {
		exec(`INSERT INTO identity_facts(id,operator_id,fact,value,asserted_by,record_id,created_at)
			VALUES ($1,$2,$3,$4::jsonb,$5,$6,COALESCE($7::timestamptz, now())) ON CONFLICT (id) DO NOTHING`,
			i.ID, i.OperatorID, i.Fact, js(i.Value), nz(i.AssertedBy), i.RecordID, opTime(ops, i.RecordID))
	}
	for _, m := range r.Memory {
		exec(`INSERT INTO memory_items(id,goal_id,operator_id,key,value,record_id,created_at)
			VALUES ($1,$2,$3,$4,$5::jsonb,$6,COALESCE($7::timestamptz, now())) ON CONFLICT (id) DO NOTHING`,
			m.ID, nz(m.GoalID), nz(m.OperatorID), m.Key, js(m.Value), m.RecordID, opTime(ops, m.RecordID))
	}
	return err
}

// Rows reads the projection back from Postgres (implements Reader).
func (p *PG) Rows(ctx context.Context, goalID string) (*Rows, error) {
	out := &Rows{}
	var err error
	q := func(sqlq string, args []any, scan func(pgx.Rows) error) {
		if err != nil {
			return
		}
		var rows pgx.Rows
		if rows, err = p.Pool.Query(ctx, sqlq, args...); err != nil {
			return
		}
		defer rows.Close()
		for rows.Next() {
			if err = scan(rows); err != nil {
				return
			}
		}
		err = rows.Err()
	}
	gf, args := "", []any{}
	if goalID != "" {
		gf, args = " WHERE goal_id=$1", []any{goalID}
	}
	idf := gf
	if goalID != "" {
		idf = " WHERE id=$1"
	}
	q(`SELECT id, COALESCE(title,''), COALESCE(originating_human_id,''), status, COALESCE(first_record_id::text,'') FROM goals`+idf, args, func(r pgx.Rows) error {
		var g GoalRow
		e := r.Scan(&g.ID, &g.Title, &g.OriginatingHumanID, &g.Status, &g.FirstRecordID)
		out.Goals = append(out.Goals, g)
		return e
	})
	q(`SELECT id::text, goal_id, step_no, COALESCE(description,''), status, COALESCE(record_id::text,'') FROM goal_steps`+gf, args, func(r pgx.Rows) error {
		var s StepRow
		e := r.Scan(&s.ID, &s.GoalID, &s.StepNo, &s.Description, &s.Status, &s.RecordID)
		out.Steps = append(out.Steps, s)
		return e
	})
	q(`SELECT id::text, COALESCE(attempt_key,''), COALESCE(goal_id,''), COALESCE(step_id::text,''), COALESCE(tool_id,''), action_hash, arguments::text,
		COALESCE(outcome,''), COALESCE(policy_version,''), COALESCE(record_id::text,''), COALESCE(result_record_id::text,'') FROM action_attempts`+gf, args, func(r pgx.Rows) error {
		var a AttemptRow
		var argText *string
		e := r.Scan(&a.ID, &a.AttemptKey, &a.GoalID, &a.StepID, &a.ToolID, &a.ActionHash, &argText, &a.Outcome, &a.PolicyVersion, &a.RecordID, &a.ResultRecordID)
		if argText != nil {
			a.Arguments = Canon([]byte(*argText))
		}
		out.Attempts = append(out.Attempts, a)
		return e
	})
	q(`SELECT id::text, COALESCE(action_attempt_id::text,''), COALESCE(goal_id,''), verifier, passed, evidence::text, COALESCE(record_id::text,'') FROM verification_results`+gf, args, func(r pgx.Rows) error {
		var v VerificationRow
		var evText *string
		e := r.Scan(&v.ID, &v.AttemptID, &v.GoalID, &v.Verifier, &v.Passed, &evText, &v.RecordID)
		if evText != nil {
			v.Evidence = Canon([]byte(*evText))
		}
		out.Verifications = append(out.Verifications, v)
		return e
	})
	q(`SELECT id::text, COALESCE(request_key,''), COALESCE(goal_id,''), action_hash, COALESCE(requested_by,''), COALESCE(decided_by,''), COALESCE(decision,''),
		COALESCE(reason,''), COALESCE(record_id::text,''), COALESCE(decision_record_id::text,'') FROM approval_requests`+gf, args, func(r pgx.Rows) error {
		var a ApprovalRow
		e := r.Scan(&a.ID, &a.RequestKey, &a.GoalID, &a.ActionHash, &a.RequestedBy, &a.DecidedBy, &a.Decision, &a.Reason, &a.RecordID, &a.DecisionRecordID)
		out.Approvals = append(out.Approvals, a)
		return e
	})
	q(`SELECT id::text, request_key, COALESCE(goal_id,''), action_hash, decision, COALESCE(decided_by,''), COALESCE(reason,''), matched, COALESCE(record_id::text,'') FROM approval_decisions`+gf, args, func(r pgx.Rows) error {
		var d DecisionRow
		e := r.Scan(&d.ID, &d.RequestKey, &d.GoalID, &d.ActionHash, &d.Decision, &d.DecidedBy, &d.Reason, &d.Matched, &d.RecordID)
		out.Decisions = append(out.Decisions, d)
		return e
	})
	bf := ""
	if goalID != "" {
		bf = " WHERE grp IN (SELECT grp FROM budget_ledger WHERE goal_id=$1)"
	}
	q(`SELECT id::text, COALESCE(grp,''), COALESCE(position,0), COALESCE(goal_id,''), COALESCE(operator_id,''), resource, COALESCE(entry_kind,''),
		delta::float8, COALESCE(balance,0)::float8, overspent, COALESCE(record_id::text,'') FROM budget_ledger`+bf, args, func(r pgx.Rows) error {
		var b BudgetRow
		e := r.Scan(&b.ID, &b.Group, &b.Position, &b.GoalID, &b.OperatorID, &b.Resource, &b.EntryKind, &b.Delta, &b.Balance, &b.Overspent, &b.RecordID)
		out.Budget = append(out.Budget, b)
		return e
	})
	q(`SELECT id::text, operator_id, fact, value::text, COALESCE(asserted_by,''), COALESCE(record_id::text,'') FROM identity_facts`, nil, func(r pgx.Rows) error {
		var i IdentityRow
		var vText *string
		e := r.Scan(&i.ID, &i.OperatorID, &i.Fact, &vText, &i.AssertedBy, &i.RecordID)
		if vText != nil {
			i.Value = Canon([]byte(*vText))
		}
		out.Identity = append(out.Identity, i)
		return e
	})
	q(`SELECT id::text, COALESCE(goal_id,''), COALESCE(operator_id,''), key, value::text, COALESCE(record_id::text,'') FROM memory_items`+gf, args, func(r pgx.Rows) error {
		var m MemoryRow
		var vText *string
		e := r.Scan(&m.ID, &m.GoalID, &m.OperatorID, &m.Key, &vText, &m.RecordID)
		if vText != nil {
			m.Value = Canon([]byte(*vText))
		}
		out.Memory = append(out.Memory, m)
		return e
	})
	q(`SELECT id, name, COALESCE(version,''), COALESCE(description,'') FROM tools`, nil, func(r pgx.Rows) error {
		var t ToolRow
		e := r.Scan(&t.ID, &t.Name, &t.Version, &t.Description)
		out.Tools = append(out.Tools, t)
		return e
	})
	q(`SELECT id, kind, COALESCE(model,''), COALESCE(model_version,'') FROM operators`, nil, func(r pgx.Rows) error {
		var o OperatorRow
		e := r.Scan(&o.ID, &o.Kind, &o.Model, &o.ModelVersion)
		out.Operators = append(out.Operators, o)
		return e
	})
	if err != nil {
		return nil, err
	}
	out.Evidence, err = p.evidence(ctx, out)
	if err != nil {
		return nil, err
	}
	out.Sort()
	return out, nil
}

func (p *PG) evidence(ctx context.Context, r *Rows) (map[string]Evidence, error) {
	ids := map[string]bool{}
	add := func(s ...string) {
		for _, x := range s {
			if x != "" {
				ids[x] = true
			}
		}
	}
	for _, x := range r.Goals {
		add(x.FirstRecordID)
	}
	for _, x := range r.Steps {
		add(x.RecordID)
	}
	for _, x := range r.Attempts {
		add(x.RecordID, x.ResultRecordID)
	}
	for _, x := range r.Verifications {
		add(x.RecordID)
	}
	for _, x := range r.Approvals {
		add(x.RecordID, x.DecisionRecordID)
	}
	for _, x := range r.Decisions {
		add(x.RecordID)
	}
	for _, x := range r.Budget {
		add(x.RecordID)
	}
	for _, x := range r.Memory {
		add(x.RecordID)
	}
	list := make([]string, 0, len(ids))
	for k := range ids {
		list = append(list, k)
	}
	out := map[string]Evidence{}
	rows, err := p.Pool.Query(ctx, `SELECT id::text, chain, seq, type, hash FROM records WHERE id::text = ANY($1)`, list)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var e Evidence
		if err := rows.Scan(&id, &e.Chain, &e.Seq, &e.Type, &e.Hash); err != nil {
			return nil, err
		}
		out[id] = e
	}
	return out, rows.Err()
}

// Check projects every record into a fresh in-memory model and compares it with
// the stored (incremental) projection: rebuild == incremental. Returns "" when equal.
func (p *PG) Check(ctx context.Context) (string, error) {
	rows, err := p.Pool.Query(ctx, recCols+` ORDER BY created_at, chain, seq`)
	if err != nil {
		return "", err
	}
	recs, err := scanRecs(rows)
	if err != nil {
		return "", err
	}
	m := NewModel()
	for _, r := range recs {
		m.Apply(r)
	}
	stored, err := p.Rows(ctx, "")
	if err != nil {
		return "", err
	}
	want := m.Rows()
	// Operators are also inserted by store.Append; compare projected ones only.
	have := map[string]bool{}
	for _, o := range want.Operators {
		have[o.ID] = true
	}
	var ops []OperatorRow
	for _, o := range stored.Operators {
		if have[o.ID] {
			ops = append(ops, o)
		}
	}
	stored.Operators = ops
	return Diff(want, stored), nil
}

// Worker runs CatchUp in the background after appends: Notify never blocks
// (a pending notification coalesces further ones), so the queue is bounded to one.
type Worker struct {
	P        *PG
	Interval time.Duration // periodic catch-up for records appended by other processes (default 30s)
	Logf     func(string, ...any)
	kick     chan struct{}
}

func NewWorker(p *PG) *Worker { return &Worker{P: p, kick: make(chan struct{}, 1), Logf: log.Printf} }

// Notify requests a catch-up (non-blocking).
func (w *Worker) Notify() {
	select {
	case w.kick <- struct{}{}:
	default:
	}
}

// Run loops until ctx is done.
func (w *Worker) Run(ctx context.Context) {
	iv := w.Interval
	if iv <= 0 {
		iv = 30 * time.Second
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	w.Notify()
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.kick:
		case <-t.C:
		}
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		st, err := w.P.CatchUp(cctx)
		cancel()
		if err != nil && ctx.Err() == nil {
			w.Logf("ledgerd: projection: %v", err)
		} else if st.Rebuilt {
			w.Logf("ledgerd: projection rebuilt (version %d): %d records", Version, st.Records)
		}
	}
}
