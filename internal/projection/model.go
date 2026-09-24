package projection

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/Celaris-dev1/Ledger/internal/canon"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

// Row types mirror the domain tables (only projected columns; timestamps excluded).

type GoalRow struct {
	ID                 string `json:"id"`
	Title              string `json:"title,omitempty"`
	OriginatingHumanID string `json:"originating_human_id,omitempty"`
	Status             string `json:"status"`
	FirstRecordID      string `json:"first_record_id,omitempty"`
}

type StepRow struct {
	ID          string `json:"id"`
	GoalID      string `json:"goal_id"`
	StepNo      int    `json:"step_no"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status"`
	RecordID    string `json:"record_id,omitempty"`
}

type AttemptRow struct {
	ID             string          `json:"id"`
	AttemptKey     string          `json:"attempt_key"`
	GoalID         string          `json:"goal_id,omitempty"`
	StepID         string          `json:"step_id,omitempty"`
	ToolID         string          `json:"tool_id,omitempty"`
	ActionHash     string          `json:"action_hash"`
	Arguments      json.RawMessage `json:"arguments,omitempty"`
	Outcome        string          `json:"outcome,omitempty"`
	PolicyVersion  string          `json:"policy_version,omitempty"`
	RecordID       string          `json:"record_id,omitempty"`
	ResultRecordID string          `json:"result_record_id,omitempty"`
}

type VerificationRow struct {
	ID        string          `json:"id"`
	AttemptID string          `json:"action_attempt_id,omitempty"`
	GoalID    string          `json:"goal_id,omitempty"`
	Verifier  string          `json:"verifier"`
	Passed    bool            `json:"passed"`
	Evidence  json.RawMessage `json:"evidence,omitempty"`
	RecordID  string          `json:"record_id"`
}

type ApprovalRow struct {
	ID               string `json:"id"`
	RequestKey       string `json:"request_key"`
	GoalID           string `json:"goal_id,omitempty"`
	ActionHash       string `json:"action_hash"`
	RequestedBy      string `json:"requested_by,omitempty"`
	DecidedBy        string `json:"decided_by,omitempty"`
	Decision         string `json:"decision,omitempty"`
	Reason           string `json:"reason,omitempty"`
	RecordID         string `json:"record_id"`
	DecisionRecordID string `json:"decision_record_id,omitempty"`
}

// Status is pending|approved|denied.
func (a ApprovalRow) Status() string {
	if a.Decision == "" {
		return "pending"
	}
	return a.Decision
}

type DecisionRow struct {
	ID         string `json:"id"`
	RequestKey string `json:"request_key"`
	GoalID     string `json:"goal_id,omitempty"`
	ActionHash string `json:"action_hash"`
	Decision   string `json:"decision"`
	DecidedBy  string `json:"decided_by,omitempty"`
	Reason     string `json:"reason,omitempty"`
	RecordID   string `json:"record_id"`
	// Matched is false when no request exists or the decision's action_hash differs
	// from the request's: such a decision never satisfies the request.
	Matched bool `json:"matched"`
}

type BudgetRow struct {
	ID         string  `json:"id"`
	Group      string  `json:"group"`
	Position   int     `json:"position"`
	GoalID     string  `json:"goal_id,omitempty"`
	OperatorID string  `json:"operator_id,omitempty"`
	Resource   string  `json:"resource"`
	EntryKind  string  `json:"entry_kind"`
	Delta      float64 `json:"delta"`
	Balance    float64 `json:"balance"`
	Overspent  bool    `json:"overspent"`
	RecordID   string  `json:"record_id"`
}

type IdentityRow struct {
	ID         string          `json:"id"`
	OperatorID string          `json:"operator_id"`
	Fact       string          `json:"fact"`
	Value      json.RawMessage `json:"value,omitempty"`
	AssertedBy string          `json:"asserted_by,omitempty"`
	RecordID   string          `json:"record_id"`
}

type MemoryRow struct {
	ID         string          `json:"id"`
	GoalID     string          `json:"goal_id,omitempty"`
	OperatorID string          `json:"operator_id,omitempty"`
	Key        string          `json:"key"`
	Value      json.RawMessage `json:"value,omitempty"`
	RecordID   string          `json:"record_id"`
}

type ToolRow struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Description string `json:"description,omitempty"`
}

type OperatorRow struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	Model        string `json:"model,omitempty"`
	ModelVersion string `json:"model_version,omitempty"`
}

// Evidence points a projected row back at its source record.
type Evidence struct {
	Chain string `json:"chain"`
	Seq   int64  `json:"seq"`
	Type  string `json:"type"`
	Hash  string `json:"hash"`
}

// Rows is a full (or goal-filtered) projection snapshot.
type Rows struct {
	Goals         []GoalRow           `json:"goals"`
	Steps         []StepRow           `json:"goal_steps"`
	Attempts      []AttemptRow        `json:"action_attempts"`
	Verifications []VerificationRow   `json:"verification_results"`
	Approvals     []ApprovalRow       `json:"approval_requests"`
	Decisions     []DecisionRow       `json:"approval_decisions"`
	Budget        []BudgetRow         `json:"budget_ledger"`
	Identity      []IdentityRow       `json:"identity_facts"`
	Memory        []MemoryRow         `json:"memory_items"`
	Tools         []ToolRow           `json:"tools"`
	Operators     []OperatorRow       `json:"operators"`
	Evidence      map[string]Evidence `json:"evidence,omitempty"`
}

func (r *Rows) merge(o *Rows) {
	r.Goals = append(r.Goals, o.Goals...)
	r.Steps = append(r.Steps, o.Steps...)
	r.Attempts = append(r.Attempts, o.Attempts...)
	r.Verifications = append(r.Verifications, o.Verifications...)
	r.Approvals = append(r.Approvals, o.Approvals...)
	r.Decisions = append(r.Decisions, o.Decisions...)
	r.Budget = append(r.Budget, o.Budget...)
	r.Identity = append(r.Identity, o.Identity...)
	r.Memory = append(r.Memory, o.Memory...)
	r.Tools = append(r.Tools, o.Tools...)
	r.Operators = append(r.Operators, o.Operators...)
}

// Sort puts every table in id order (for comparison and stable output).
func (r *Rows) Sort() {
	sort.Slice(r.Goals, func(i, j int) bool { return r.Goals[i].ID < r.Goals[j].ID })
	sort.Slice(r.Steps, func(i, j int) bool { return r.Steps[i].ID < r.Steps[j].ID })
	sort.Slice(r.Attempts, func(i, j int) bool { return r.Attempts[i].ID < r.Attempts[j].ID })
	sort.Slice(r.Verifications, func(i, j int) bool { return r.Verifications[i].ID < r.Verifications[j].ID })
	sort.Slice(r.Approvals, func(i, j int) bool { return r.Approvals[i].ID < r.Approvals[j].ID })
	sort.Slice(r.Decisions, func(i, j int) bool { return r.Decisions[i].ID < r.Decisions[j].ID })
	sort.Slice(r.Budget, func(i, j int) bool {
		if r.Budget[i].Group != r.Budget[j].Group {
			return r.Budget[i].Group < r.Budget[j].Group
		}
		return r.Budget[i].Position < r.Budget[j].Position
	})
	sort.Slice(r.Identity, func(i, j int) bool { return r.Identity[i].ID < r.Identity[j].ID })
	sort.Slice(r.Memory, func(i, j int) bool { return r.Memory[i].ID < r.Memory[j].ID })
	sort.Slice(r.Tools, func(i, j int) bool { return r.Tools[i].ID < r.Tools[j].ID })
	sort.Slice(r.Operators, func(i, j int) bool { return r.Operators[i].ID < r.Operators[j].ID })
}

// Diff returns "" when both snapshots have identical rows (evidence ignored),
// otherwise a short description of the first differing table.
func Diff(a, b *Rows) string {
	x, y := *a, *b
	x.Evidence, y.Evidence = nil, nil
	x.Sort()
	y.Sort()
	va, vb := reflect.ValueOf(x), reflect.ValueOf(y)
	for i := 0; i < va.NumField(); i++ {
		fa, fb := va.Field(i), vb.Field(i)
		if fa.Len() == 0 && fb.Len() == 0 {
			continue
		}
		if !reflect.DeepEqual(fa.Interface(), fb.Interface()) {
			ja, _ := json.Marshal(fa.Interface())
			jb, _ := json.Marshal(fb.Interface())
			return fmt.Sprintf("%s differs:\n  a=%s\n  b=%s", va.Type().Field(i).Name, trunc(ja), trunc(jb))
		}
	}
	return ""
}

func trunc(b []byte) string {
	if len(b) > 2000 {
		return string(b[:2000]) + "..."
	}
	return string(b)
}

func fs(f map[string]any, k string) string { return payload(f).s(k) }

func raw(v any) json.RawMessage {
	if v == nil {
		return nil
	}
	b, err := canon.Marshal(v)
	if err != nil || string(b) == "null" {
		return nil
	}
	c, _ := canon.CanonicalBytes(b)
	return c
}

// Canon canonicalises JSON bytes (used when reading jsonb back from Postgres).
func Canon(b []byte) json.RawMessage {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	c, err := canon.CanonicalBytes(b)
	if err != nil {
		return json.RawMessage(b)
	}
	return c
}

// AttemptUUID and StepUUID are the deterministic row ids.
func AttemptUUID(key string) string { return DetUUID("attempt/" + key) }
func StepUUID(goal string, no int) string {
	return DetUUID(fmt.Sprintf("step/%s/%d", goal, no))
}
func ApprovalUUID(key string) string { return DetUUID("approval/" + key) }

// Fold computes the rows of one group from all of its ops.
func Fold(group string, ops []Op) *Rows {
	sortOps(ops)
	out := &Rows{}
	if len(ops) == 0 {
		return out
	}
	kind := group[:strings.IndexByte(group, ':')]
	switch kind {
	case "goal":
		g := GoalRow{ID: strings.TrimPrefix(group, "goal:"), Status: "open", OriginatingHumanID: fs(ops[0].F, "human"), FirstRecordID: ops[0].RecordID}
		for _, o := range ops {
			if t := fs(o.F, "title"); t != "" {
				g.Title = t
			}
			if s := fs(o.F, "status"); s != "" {
				g.Status = s
			}
		}
		out.Goals = append(out.Goals, g)
	case "operator":
		r := OperatorRow{ID: strings.TrimPrefix(group, "operator:")}
		fallback := ""
		for _, o := range ops {
			if k := fs(o.F, "kind"); k != "" {
				if o.F["explicit"] == true && r.Kind == "" {
					r.Kind = k
				} else if fallback == "" {
					fallback = k
				}
			}
			if v := fs(o.F, "model"); v != "" {
				r.Model = v
			}
			if v := fs(o.F, "model_version"); v != "" {
				r.ModelVersion = v
			}
		}
		r.Kind = firstNonEmpty(r.Kind, fallback, "agent")
		out.Operators = append(out.Operators, r)
	case "tool":
		r := ToolRow{ID: strings.TrimPrefix(group, "tool:")}
		for _, o := range ops {
			if v := fs(o.F, "name"); v != "" {
				r.Name = v
			}
			if v := fs(o.F, "version"); v != "" {
				r.Version = v
			}
			if v := fs(o.F, "description"); v != "" {
				r.Description = v
			}
		}
		if r.Name == "" {
			r.Name = r.ID
		}
		out.Tools = append(out.Tools, r)
	case "step":
		r := StepRow{GoalID: ops[0].GoalID, Status: "proposed"}
		no, _ := payload(ops[0].F).num("step_no")
		r.StepNo = int(no)
		r.ID = StepUUID(r.GoalID, r.StepNo)
		for _, o := range ops {
			if v := fs(o.F, "description"); v != "" {
				r.Description = v
			}
			if v := fs(o.F, "status"); v != "" {
				r.Status = v
			}
			if o.F["planned"] == true && r.RecordID == "" {
				r.RecordID = o.RecordID
			}
		}
		out.Steps = append(out.Steps, r)
	case "attempt":
		key := strings.TrimPrefix(group, "attempt:")
		r := AttemptRow{ID: AttemptUUID(key), AttemptKey: key}
		for _, o := range ops {
			if r.GoalID == "" {
				r.GoalID = o.GoalID
			}
			switch o.Kind {
			case "attempt":
				if r.RecordID != "" {
					continue // first attempt record wins
				}
				r.RecordID, r.GoalID = o.RecordID, o.GoalID
				r.ToolID, r.ActionHash, r.PolicyVersion = fs(o.F, "tool"), fs(o.F, "action_hash"), fs(o.F, "policy_version")
				r.Arguments = raw(o.F["arguments"])
				if n, ok := payload(o.F).num("step_no"); ok && o.GoalID != "" {
					r.StepID = StepUUID(o.GoalID, int(n))
				}
			case "attempt_result":
				r.Outcome, r.ResultRecordID = fs(o.F, "outcome"), o.RecordID
			}
		}
		out.Attempts = append(out.Attempts, r)
	case "approval":
		key := strings.TrimPrefix(group, "approval:")
		var req *ApprovalRow
		for _, o := range ops {
			if o.Kind == "approval_request" && req == nil {
				req = &ApprovalRow{ID: ApprovalUUID(key), RequestKey: key, GoalID: o.GoalID, ActionHash: fs(o.F, "action_hash"),
					RequestedBy: fs(o.F, "requested_by"), Reason: fs(o.F, "reason"), RecordID: o.RecordID}
			}
		}
		for _, o := range ops {
			if o.Kind != "approval_decision" {
				continue
			}
			d := DecisionRow{ID: fs(o.F, "row_id"), RequestKey: key, GoalID: o.GoalID, ActionHash: fs(o.F, "action_hash"),
				Decision: fs(o.F, "decision"), DecidedBy: fs(o.F, "decided_by"), Reason: fs(o.F, "reason"), RecordID: o.RecordID}
			d.Matched = req != nil && d.ActionHash != "" && d.ActionHash == req.ActionHash
			if d.Matched && req.Decision == "" {
				req.Decision, req.DecidedBy, req.DecisionRecordID = d.Decision, d.DecidedBy, d.RecordID
				if d.Reason != "" {
					req.Reason = d.Reason
				}
			}
			out.Decisions = append(out.Decisions, d)
		}
		if req != nil {
			out.Approvals = append(out.Approvals, *req)
		}
	case "budget":
		allocated := false
		for _, o := range ops {
			if fs(o.F, "entry_kind") == "allocation" {
				allocated = true
			}
		}
		bal := 0.0
		for i, o := range ops {
			d, _ := payload(o.F).num("delta")
			bal += d
			kind := fs(o.F, "entry_kind")
			out.Budget = append(out.Budget, BudgetRow{ID: fs(o.F, "row_id"), Group: group, Position: i, GoalID: o.GoalID, OperatorID: fs(o.F, "operator_id"),
				Resource: fs(o.F, "resource"), EntryKind: kind, Delta: d, Balance: bal, Overspent: allocated && kind == "charge" && bal < 0, RecordID: o.RecordID})
		}
	case "row":
		o := ops[0]
		switch o.Kind {
		case "verification":
			r := VerificationRow{ID: fs(o.F, "row_id"), GoalID: o.GoalID, Verifier: fs(o.F, "verifier"), Evidence: raw(o.F["evidence"]), RecordID: o.RecordID}
			r.Passed, _ = o.F["passed"].(bool)
			if a := fs(o.F, "attempt_id"); a != "" {
				r.AttemptID = AttemptUUID(a)
			}
			out.Verifications = append(out.Verifications, r)
		case "identity":
			out.Identity = append(out.Identity, IdentityRow{ID: fs(o.F, "row_id"), OperatorID: fs(o.F, "operator_id"), Fact: fs(o.F, "fact"),
				Value: raw(o.F["value"]), AssertedBy: fs(o.F, "asserted_by"), RecordID: o.RecordID})
		case "memory":
			out.Memory = append(out.Memory, MemoryRow{ID: fs(o.F, "row_id"), GoalID: o.GoalID, OperatorID: fs(o.F, "operator_id"), Key: fs(o.F, "key"),
				Value: raw(o.F["value"]), RecordID: o.RecordID})
		}
	}
	return out
}

// GroupOrder is the order in which group kinds are written (FK dependencies first).
var GroupOrder = []string{"operator", "tool", "goal", "step", "attempt", "approval", "budget", "row"}

func groupKind(g string) string { return g[:strings.IndexByte(g, ':')] }

// Model is an in-memory projection: the same ops and folds the Postgres
// projector uses, without a database. Safe for concurrent use.
type Model struct {
	mu      sync.Mutex
	groups  map[string]map[string]Op
	records map[string]Evidence
	cursors map[string]int64
	unknown map[string]int
}

func NewModel() *Model {
	return &Model{groups: map[string]map[string]Op{}, records: map[string]Evidence{}, cursors: map[string]int64{}, unknown: map[string]int{}}
}

// Apply projects one record (idempotent: re-applying changes nothing).
func (m *Model) Apply(rec store.Record) {
	ops, mapped := Map(rec)
	m.mu.Lock()
	defer m.mu.Unlock()
	if !mapped {
		m.unknown[rec.Type]++
	}
	m.records[rec.ID] = Evidence{Chain: rec.Chain, Seq: rec.Seq, Type: rec.Type, Hash: rec.Hash}
	if rec.Seq > m.cursors[rec.Chain] {
		m.cursors[rec.Chain] = rec.Seq
	}
	for _, o := range ops {
		g := m.groups[o.Group]
		if g == nil {
			g = map[string]Op{}
			m.groups[o.Group] = g
		}
		g[o.ID] = o
	}
}

// Rows folds every group.
func (m *Model) Rows() *Rows {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := &Rows{Evidence: map[string]Evidence{}}
	for g, ops := range m.groups {
		list := make([]Op, 0, len(ops))
		for _, o := range ops {
			list = append(list, o)
		}
		out.merge(Fold(g, list))
	}
	for k, v := range m.records {
		out.Evidence[k] = v
	}
	out.Sort()
	return out
}

// Cursor returns the highest projected seq for a chain.
func (m *Model) Cursor(chain string) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cursors[chain]
}
