package projection

import (
	"context"
	"sort"
)

// Reader is what the query API needs; implemented by *PG and *Model.
type Reader interface {
	// Rows returns the projection; goalID != "" limits goal-scoped tables to that goal
	// (budget lines: every group that has a line for the goal).
	Rows(ctx context.Context, goalID string) (*Rows, error)
}

// RowsFor returns the in-memory projection filtered to one goal ("" = all).
func (m *Model) RowsFor(_ context.Context, goalID string) (*Rows, error) {
	return FilterGoal(m.Rows(), goalID), nil
}

// ModelReader adapts *Model to Reader.
type ModelReader struct{ M *Model }

func (r ModelReader) Rows(ctx context.Context, goalID string) (*Rows, error) {
	return r.M.RowsFor(ctx, goalID)
}

// FilterGoal keeps only rows of one goal ("" keeps everything).
func FilterGoal(all *Rows, goal string) *Rows {
	if goal == "" {
		return all
	}
	out := &Rows{Evidence: all.Evidence, Tools: all.Tools, Operators: all.Operators, Identity: all.Identity}
	for _, g := range all.Goals {
		if g.ID == goal {
			out.Goals = append(out.Goals, g)
		}
	}
	for _, s := range all.Steps {
		if s.GoalID == goal {
			out.Steps = append(out.Steps, s)
		}
	}
	for _, a := range all.Attempts {
		if a.GoalID == goal {
			out.Attempts = append(out.Attempts, a)
		}
	}
	for _, v := range all.Verifications {
		if v.GoalID == goal {
			out.Verifications = append(out.Verifications, v)
		}
	}
	for _, a := range all.Approvals {
		if a.GoalID == goal {
			out.Approvals = append(out.Approvals, a)
		}
	}
	for _, d := range all.Decisions {
		if d.GoalID == goal {
			out.Decisions = append(out.Decisions, d)
		}
	}
	groups := map[string]bool{}
	for _, b := range all.Budget {
		if b.GoalID == goal {
			groups[b.Group] = true
		}
	}
	for _, b := range all.Budget {
		if groups[b.Group] {
			out.Budget = append(out.Budget, b)
		}
	}
	for _, m := range all.Memory {
		if m.GoalID == goal {
			out.Memory = append(out.Memory, m)
		}
	}
	return out
}

// EvidenceRef is a record id plus where/what it is.
type EvidenceRef struct {
	RecordID string `json:"record_id"`
	Evidence
}

func ev(r *Rows, ids ...string) []EvidenceRef {
	var out []EvidenceRef
	for _, id := range ids {
		if id == "" {
			continue
		}
		out = append(out, EvidenceRef{RecordID: id, Evidence: r.Evidence[id]})
	}
	return out
}

type VerificationNode struct {
	VerificationRow
	Evidence []EvidenceRef `json:"evidence_records"`
}

type ApprovalNode struct {
	ApprovalRow
	Status    string        `json:"status"`
	Decisions []DecisionRow `json:"decisions"`
	Evidence  []EvidenceRef `json:"evidence_records"`
}

type AttemptNode struct {
	AttemptRow
	// Approval summarises approvals bound to this exact action_hash in the goal:
	// approved | denied | pending | none.
	Approval      string             `json:"approval"`
	Verifications []VerificationNode `json:"verifications"`
	Approvals     []ApprovalNode     `json:"approvals"`
	Evidence      []EvidenceRef      `json:"evidence_records"`
}

type StepNode struct {
	StepRow
	Attempts []AttemptNode `json:"attempts"`
	Evidence []EvidenceRef `json:"evidence_records"`
}

// GoalTree is the response of GET /v1/goals/{id}.
type GoalTree struct {
	Goal              GoalRow            `json:"goal"`
	Evidence          []EvidenceRef      `json:"evidence_records"`
	Steps             []StepNode         `json:"steps"`
	UnstepedAttempts  []AttemptNode      `json:"attempts_without_step"`
	GoalVerifications []VerificationNode `json:"verifications_without_attempt"`
	Approvals         []ApprovalNode     `json:"approvals"`
	Budget            []BudgetSummary    `json:"budgets"`
	Memory            []MemoryRow        `json:"memory_items"`
}

func approvalNodes(r *Rows, list []ApprovalRow) []ApprovalNode {
	var out []ApprovalNode
	// index decisions once: scanning all decisions per request was O(requests x decisions)
	byKey := map[string][]DecisionRow{}
	for _, d := range r.Decisions {
		byKey[d.RequestKey] = append(byKey[d.RequestKey], d)
	}
	for _, a := range list {
		n := ApprovalNode{ApprovalRow: a, Status: a.Status(), Evidence: ev(r, a.RecordID, a.DecisionRecordID), Decisions: []DecisionRow{}}
		n.Decisions = append(n.Decisions, byKey[a.RequestKey]...)
		out = append(out, n)
	}
	return out
}

// ApprovalStatusFor reports whether an action hash is approved within a goal:
// only an approval request for exactly this hash with a matched approving decision counts.
func ApprovalStatusFor(approvals []ApprovalRow, actionHash string) string {
	st := "none"
	for _, a := range approvals {
		if a.ActionHash != actionHash || actionHash == "" {
			continue
		}
		switch a.Status() {
		case "denied":
			return "denied"
		case "approved":
			st = "approved"
		case "pending":
			if st == "none" {
				st = "pending"
			}
		}
	}
	return st
}

// BuildTree assembles goal → steps → attempts → verifications/approvals.
func BuildTree(r *Rows, goalID string) (*GoalTree, bool) {
	r = FilterGoal(r, goalID)
	if len(r.Goals) == 0 {
		return nil, false
	}
	t := &GoalTree{Goal: r.Goals[0], Evidence: ev(r, r.Goals[0].FirstRecordID), Steps: []StepNode{}, UnstepedAttempts: []AttemptNode{},
		GoalVerifications: []VerificationNode{}, Memory: r.Memory, Budget: Budgets(r, goalID)}
	t.Approvals = approvalNodes(r, r.Approvals)
	stepIdx := map[string]int{}
	steps := append([]StepRow(nil), r.Steps...)
	sort.Slice(steps, func(i, j int) bool { return steps[i].StepNo < steps[j].StepNo })
	for _, s := range steps {
		stepIdx[s.ID] = len(t.Steps)
		t.Steps = append(t.Steps, StepNode{StepRow: s, Attempts: []AttemptNode{}, Evidence: ev(r, s.RecordID)})
	}
	attemptVer := map[string][]VerificationNode{}
	for _, v := range r.Verifications {
		n := VerificationNode{VerificationRow: v, Evidence: ev(r, v.RecordID)}
		if v.AttemptID == "" {
			t.GoalVerifications = append(t.GoalVerifications, n)
		} else {
			attemptVer[v.AttemptID] = append(attemptVer[v.AttemptID], n)
		}
	}
	attempts := append([]AttemptRow(nil), r.Attempts...)
	sort.Slice(attempts, func(i, j int) bool {
		ei, ej := r.Evidence[attempts[i].RecordID], r.Evidence[attempts[j].RecordID]
		if ei.Chain != ej.Chain {
			return ei.Chain < ej.Chain
		}
		if ei.Seq != ej.Seq {
			return ei.Seq < ej.Seq
		}
		return attempts[i].ID < attempts[j].ID
	})
	// index approvals by action hash once (per-attempt scans were O(attempts x approvals));
	// order within a hash is preserved, so ApprovalStatusFor over the subset is unchanged.
	rowsByHash, nodesByHash := map[string][]ApprovalRow{}, map[string][]ApprovalNode{}
	for _, ap := range r.Approvals {
		rowsByHash[ap.ActionHash] = append(rowsByHash[ap.ActionHash], ap)
	}
	for _, ap := range t.Approvals {
		nodesByHash[ap.ActionHash] = append(nodesByHash[ap.ActionHash], ap)
	}
	for _, a := range attempts {
		n := AttemptNode{AttemptRow: a, Approval: ApprovalStatusFor(rowsByHash[a.ActionHash], a.ActionHash), Verifications: attemptVer[a.ID],
			Evidence: ev(r, a.RecordID, a.ResultRecordID), Approvals: []ApprovalNode{}}
		if n.Verifications == nil {
			n.Verifications = []VerificationNode{}
		}
		if a.ActionHash != "" {
			n.Approvals = append(n.Approvals, nodesByHash[a.ActionHash]...)
		}
		if i, ok := stepIdx[a.StepID]; ok && a.StepID != "" {
			t.Steps[i].Attempts = append(t.Steps[i].Attempts, n)
		} else {
			t.UnstepedAttempts = append(t.UnstepedAttempts, n)
		}
	}
	return t, true
}

// GoalSummary is one entry of GET /v1/goals.
type GoalSummary struct {
	GoalRow
	Steps         int `json:"steps"`
	Attempts      int `json:"attempts"`
	Verifications int `json:"verifications"`
	Failed        int `json:"failed_verifications"`
	Pending       int `json:"pending_approvals"`
	Overspent     int `json:"overspent_lines"`
}

// Goals summarises all goals.
func Goals(r *Rows) []GoalSummary {
	idx := map[string]*GoalSummary{}
	out := make([]GoalSummary, len(r.Goals))
	for i, g := range r.Goals {
		out[i] = GoalSummary{GoalRow: g}
		idx[g.ID] = &out[i]
	}
	for _, s := range r.Steps {
		if g := idx[s.GoalID]; g != nil {
			g.Steps++
		}
	}
	for _, a := range r.Attempts {
		if g := idx[a.GoalID]; g != nil {
			g.Attempts++
		}
	}
	for _, v := range r.Verifications {
		if g := idx[v.GoalID]; g != nil {
			g.Verifications++
			if !v.Passed {
				g.Failed++
			}
		}
	}
	for _, a := range r.Approvals {
		if g := idx[a.GoalID]; g != nil && a.Status() == "pending" {
			g.Pending++
		}
	}
	for _, b := range r.Budget {
		if g := idx[b.GoalID]; g != nil && b.Overspent {
			g.Overspent++
		}
	}
	return out
}

// Approvals filters approval requests by status ("" = all).
func Approvals(r *Rows, status string) []ApprovalNode {
	var list []ApprovalRow
	for _, a := range r.Approvals {
		if status == "" || a.Status() == status {
			list = append(list, a)
		}
	}
	out := approvalNodes(r, list)
	if out == nil {
		out = []ApprovalNode{}
	}
	return out
}

// BudgetSummary is one budget group with its running lines.
type BudgetSummary struct {
	Group     string      `json:"group"`
	Resource  string      `json:"resource"`
	Allocated float64     `json:"allocated"`
	Spent     float64     `json:"spent"`
	Balance   float64     `json:"balance"`
	Overspent bool        `json:"overspent"`
	Lines     []BudgetRow `json:"lines"`
}

// Budgets groups budget lines (for GET /v1/budgets/{goal}).
func Budgets(r *Rows, goal string) []BudgetSummary {
	r = FilterGoal(r, goal)
	var out []BudgetSummary
	idx := map[string]int{}
	for _, b := range r.Budget {
		i, ok := idx[b.Group]
		if !ok {
			i = len(out)
			idx[b.Group] = i
			out = append(out, BudgetSummary{Group: b.Group, Resource: b.Resource})
		}
		s := &out[i]
		s.Lines = append(s.Lines, b)
		if b.Delta >= 0 {
			s.Allocated += b.Delta
		} else {
			s.Spent -= b.Delta
		}
		s.Balance = b.Balance
		s.Overspent = s.Overspent || b.Overspent
	}
	if out == nil {
		out = []BudgetSummary{}
	}
	return out
}
