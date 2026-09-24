package projection

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Celaris-dev1/Ledger/internal/store"
	"github.com/Celaris-dev1/Ledger/internal/testfix"
)

var update = flag.Bool("update", false, "rewrite golden files")

var A = testfix.Actors

// streams are the golden fixtures: one per product plus the ledger.* vocabulary.
func streams() map[string]*testfix.Builder {
	out := map[string]*testfix.Builder{}

	b := testfix.New()
	g := "g-ledger"
	b.Add("ledger", "ledger.goal.created", g, A("alice", "agent-1"), map[string]any{"title": "Refund customer 42"})
	b.Add("ledger", "ledger.tool.registered", "", A("alice"), map[string]any{"tool_id": "payments.refund", "name": "Refund", "version": "2", "description": "issue refund"})
	b.Add("ledger", "ledger.step.planned", g, A("alice", "agent-1"), map[string]any{"step_no": 1, "description": "look up order"})
	b.Add("ledger", "ledger.step.planned", g, A("alice", "agent-1"), map[string]any{"step_no": 2, "description": "refund"})
	b.Add("ledger", "ledger.action.attempted", g, A("alice", "agent-1"), map[string]any{"attempt_id": "at-1", "step_no": 2, "tool": "payments.refund", "action": map[string]any{"tool": "payments.refund", "order": 42, "amount": "19.99"}})
	b.Add("ledger", "ledger.approval.requested", g, A("alice", "agent-1"), map[string]any{"request_id": "r-1", "action": map[string]any{"tool": "payments.refund", "order": 42, "amount": "19.99"}, "reason": "refund > 10"})
	b.Add("ledger", "ledger.approval.granted", g, A("alice"), map[string]any{"request_id": "r-1", "action": map[string]any{"tool": "payments.refund", "order": 42, "amount": "19.99"}})
	b.Add("ledger", "ledger.approval.requested", g, A("alice", "agent-1"), map[string]any{"request_id": "r-2", "action_hash": "hash-of-something-else"})
	b.Add("ledger", "ledger.approval.denied", g, A("alice", "svc:risk"), map[string]any{"request_id": "r-2", "action_hash": "hash-of-something-else", "reason": "no"})
	b.Add("ledger", "ledger.action.completed", g, A("alice", "agent-1"), map[string]any{"attempt_id": "at-1", "outcome": "succeeded", "result": map[string]any{"refund_id": "rf-9"}})
	b.Add("ledger", "ledger.verification.recorded", g, A("alice", "svc:checker"), map[string]any{"attempt_id": "at-1", "verifier": "ledger-check", "passed": true, "evidence": map[string]any{"balance": "ok"}})
	b.Add("ledger", "ledger.verification.recorded", g, A("alice", "svc:checker"), map[string]any{"verifier": "goal-review", "passed": false})
	b.Add("ledger", "ledger.budget.allocated", g, A("alice"), map[string]any{"resource": "usd", "amount": 20})
	b.Add("ledger", "ledger.budget.charged", g, A("alice", "agent-1"), map[string]any{"resource": "usd", "amount": 19.99})
	b.Add("ledger", "ledger.budget.charged", g, A("alice", "agent-1"), map[string]any{"resource": "usd", "amount": 5})
	b.Add("ledger", "ledger.identity.asserted", "", A("alice", "svc:idp"), map[string]any{"operator_id": "agent-1", "fact": "team", "value": "payments"})
	b.Add("ledger", "ledger.memory.written", g, A("alice", "agent-1"), map[string]any{"key": "customer", "value": map[string]any{"id": 42}})
	b.Add("ledger", "ledger.step.status", g, A("alice", "agent-1"), map[string]any{"step_no": 1, "status": "done"})
	b.Add("ledger", "ledger.goal.status", g, A("alice"), map[string]any{"status": "done"})
	out["ledger"] = b

	b = testfix.New()
	b.Add("gate", "gate.policy.version.created", "", A("admin"), map[string]any{"scope": "acme", "version": 3})
	b.Add("gate", "gate.run.started", "g-gate", A("alice", "coder"), map[string]any{"run_id": "run-1", "repo": "acme/api", "base": "main", "head": "abc", "files": []string{"a.go"}})
	b.Add("gate", "gate.stage.completed", "g-gate", A("alice", "coder"), map[string]any{"run_id": "run-1", "stage": "tests", "status": "pass", "risk": 0.1, "findings": 0})
	b.Add("gate", "gate.stage.completed", "g-gate", A("alice", "coder"), map[string]any{"run_id": "run-1", "stage": "security", "status": "fail", "risk": 0.9, "findings": 1})
	b.Add("gate", "gate.run.decided", "g-gate", A("alice", "coder"), map[string]any{"run_id": "run-1", "score": 0.3, "decision": "block"})
	b.Add("gate", "gate.run.enforced", "g-gate", A("alice", "coder"), map[string]any{"run_id": "run-1", "decision": "block", "reported_decision": "pass", "forced": []string{"security"}})
	b.Add("gate", "gate.admin.token.created", "", A("admin"), map[string]any{"label": "ci"})
	out["gate"] = b

	b = testfix.New()
	b.Add("proof", "proof.fetch.captured", "prun-1", A("alice", "svc:proof"), map[string]any{"capture_id": "c1", "run_id": "prun-1", "url": "https://example.com/", "fetched": true, "compliant": true, "robots_allowed": true, "content_sha256": "abc"})
	b.Add("proof", "proof.fetch.captured", "prun-1", A("alice", "svc:proof"), map[string]any{"capture_id": "c2", "run_id": "prun-1", "url": "https://example.com/private", "fetched": false, "compliant": false, "robots_allowed": false, "violations": []string{"robots"}})
	b.Add("proof", "proof.manifest.signed", "prun-1", A("alice", "svc:proof"), map[string]any{"run_id": "prun-1", "seq": 1, "manifest_hash": "mh", "captures_root": "cr", "capture_count": 2, "key_id": "k"})
	out["proof"] = b

	b = testfix.New()
	b.Add("warrant", "warrant.token.issued", "g-w", A("alice", "agent-a"), map[string]any{"token_id": "t1", "subject": "agent-a", "depth": 0, "max_depth": 1, "max_calls": 1, "scopes": []string{"s3:get"}, "goal_id": "g-w"})
	b.Add("warrant", "warrant.call.allowed", "", A("alice", "agent-a"), map[string]any{"token_id": "t1", "tool": "s3.get", "resource": "b/k", "action_hash": "h1", "reason": "ok"})
	b.Add("warrant", "warrant.call.allowed", "", A("alice", "agent-a"), map[string]any{"token_id": "t1", "tool": "s3.get", "resource": "b/k2", "action_hash": "h2", "reason": "ok"})
	b.Add("warrant", "warrant.call.denied", "", A("alice", "agent-a"), map[string]any{"token_id": "t1", "tool": "s3.put", "resource": "b/k", "action_hash": "h3", "reason": "scope"})
	b.Add("warrant", "warrant.token.revoked", "", A("alice"), map[string]any{"token_id": "t1", "reason": "done", "revoked_by": "alice"})
	out["warrant"] = b

	b = testfix.New()
	b.Add("harbour", "harbour.goal.transition", "g-h", A("alice", "agent-h"), map[string]any{"from": "", "to": "proposed", "goal_name": "nightly"})
	b.Add("harbour", "harbour.effect.intent", "g-h", A("alice", "agent-h", "svc:w1"), map[string]any{"effect_id": 7, "step": 1, "tool": "email.send", "idem_key": "k7", "args": map[string]any{"to": "x@example.com"}, "goal_name": "nightly"})
	b.Add("harbour", "harbour.effect.result", "g-h", A("alice", "agent-h", "svc:w1"), map[string]any{"effect_id": 7, "step": 1, "tool": "email.send", "idem_key": "k7", "status": "committed", "via": "run", "goal_name": "nightly"})
	b.Add("harbour", "harbour.effect.intent", "g-h", A("alice", "agent-h", "svc:w1"), map[string]any{"effect_id": 8, "step": 2, "tool": "db.write", "idem_key": "k8", "args": map[string]any{"row": 1}, "goal_name": "nightly"})
	b.Add("harbour", "harbour.goal.transition", "g-h", A("alice", "agent-h"), map[string]any{"from": "running", "to": "paused", "goal_name": "nightly"})
	out["harbour"] = b

	b = testfix.New()
	b.Add("bench", "bench.task.mined", "task-1", A("carol", "svc:bench"), map[string]any{"task_id": "task-1", "repo": "acme/api", "commit": "c1"})
	b.Add("bench", "bench.run.scored", "task-1", A("carol", "agent-b"), map[string]any{"run_id": "br-1", "task_id": "task-1", "passed": false, "failure_mode": "tests"})
	out["bench"] = b
	return out
}

func project(recs []store.Record) *Rows {
	m := NewModel()
	for _, r := range recs {
		m.Apply(r)
	}
	return m.Rows()
}

func TestGolden(t *testing.T) {
	for name, b := range streams() {
		t.Run(name, func(t *testing.T) {
			got, _ := json.MarshalIndent(project(b.Recs), "", "  ")
			path := filepath.Join("testdata", "golden", name+".json")
			if *update {
				_ = os.MkdirAll(filepath.Dir(path), 0o755)
				if err := os.WriteFile(path, append(got, '\n'), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run go test -update)", err)
			}
			if strings.TrimSpace(string(want)) != strings.TrimSpace(string(got)) {
				t.Fatalf("golden mismatch for %s (run go test ./internal/projection -update and review the diff)\n%s", name, got)
			}
		})
	}
}

// Every documented type must be exercised by a fixture and be mapped.
func TestEveryTypeMapped(t *testing.T) {
	seen := map[string]bool{}
	for _, b := range streams() {
		for _, r := range b.Recs {
			if _, mapped := Map(r); !mapped {
				t.Errorf("%s not mapped", r.Type)
			}
			seen[r.Type] = true
		}
	}
	for _, v := range Vocabulary {
		if !seen[v.Type] {
			t.Errorf("vocabulary type %s has no golden fixture", v.Type)
		}
	}
	for _, m := range ProductMappings {
		typ := strings.Replace(m.Type, "*", "token.created", 1)
		if !seen[typ] {
			t.Errorf("product type %s has no golden fixture", m.Type)
		}
	}
	if _, mapped := Map(store.Record{Type: "something.else", ActorChain: []byte(`[]`), Payload: []byte(`{}`)}); mapped {
		t.Error("unknown type reported as mapped")
	}
}

func TestLedgerSemantics(t *testing.T) {
	r := project(streams()["ledger"].Recs)
	tree, ok := BuildTree(r, "g-ledger")
	if !ok {
		t.Fatal("no goal")
	}
	if tree.Goal.Title != "Refund customer 42" || tree.Goal.Status != "done" || tree.Goal.OriginatingHumanID != "alice" {
		t.Fatalf("goal: %+v", tree.Goal)
	}
	if len(tree.Steps) != 2 || tree.Steps[0].Status != "done" || len(tree.Steps[1].Attempts) != 1 {
		t.Fatalf("steps: %+v", tree.Steps)
	}
	at := tree.Steps[1].Attempts[0]
	wantHash := ActionHash(map[string]any{"tool": "payments.refund", "order": 42, "amount": "19.99"})
	if at.ActionHash != wantHash || at.Outcome != "succeeded" || at.Approval != "approved" || len(at.Verifications) != 1 || len(at.Evidence) != 2 {
		t.Fatalf("attempt: %+v", at)
	}
	if at.Evidence[0].Hash == "" || at.Evidence[0].Chain != "ledger" {
		t.Fatalf("evidence missing hash: %+v", at.Evidence)
	}
	if len(tree.GoalVerifications) != 1 || tree.GoalVerifications[0].Passed {
		t.Fatalf("goal verifications: %+v", tree.GoalVerifications)
	}
}

// An approval for a different action hash never satisfies the request.
func TestApprovalHashBinding(t *testing.T) {
	b := testfix.New()
	actX := map[string]any{"tool": "wire", "amount": 10}
	actY := map[string]any{"tool": "wire", "amount": 10000}
	b.Add("ledger", "ledger.action.attempted", "g", A("alice", "bot"), map[string]any{"attempt_id": "a1", "tool": "wire", "action": actY})
	b.Add("ledger", "ledger.approval.requested", "g", A("alice", "bot"), map[string]any{"request_id": "r1", "action": actY})
	// approval of X presented against request r1 (for Y): must not count
	b.Add("ledger", "ledger.approval.granted", "g", A("alice"), map[string]any{"request_id": "r1", "action": actX})
	// a claimed hash that disagrees with the canonical action is ignored in favour of the action
	b.Add("ledger", "ledger.approval.granted", "g", A("alice"), map[string]any{"request_id": "r1", "action": actX, "action_hash": ActionHash(actY)})
	r := project(b.Recs)
	if len(r.Approvals) != 1 || r.Approvals[0].Status() != "pending" {
		t.Fatalf("mismatched approval satisfied the request: %+v", r.Approvals)
	}
	if len(r.Decisions) != 2 || r.Decisions[0].Matched || r.Decisions[1].Matched {
		t.Fatalf("decisions: %+v", r.Decisions)
	}
	if st := ApprovalStatusFor(r.Approvals, ActionHash(actY)); st != "pending" {
		t.Fatalf("status for Y: %s", st)
	}
	if st := ApprovalStatusFor(r.Approvals, ActionHash(actX)); st != "none" {
		t.Fatalf("status for X: %s", st)
	}
	// the correct approval satisfies it
	b.Add("ledger", "ledger.approval.granted", "g", A("alice"), map[string]any{"request_id": "r1", "action": actY})
	r = project(b.Recs)
	if r.Approvals[0].Status() != "approved" || ApprovalStatusFor(r.Approvals, ActionHash(actY)) != "approved" {
		t.Fatalf("matching approval not applied: %+v", r.Approvals)
	}
	tree, _ := BuildTree(r, "g")
	if tree.UnstepedAttempts[0].Approval != "approved" {
		t.Fatalf("attempt approval: %+v", tree.UnstepedAttempts[0])
	}
	// decision arriving before its request (different chain order) still binds correctly
	b2 := testfix.New()
	b2.Add("ledger", "ledger.approval.granted", "g", A("alice"), map[string]any{"request_id": "r9", "action": actY})
	b2.Add("ledger", "ledger.approval.requested", "g", A("alice", "bot"), map[string]any{"request_id": "r9", "action": actY})
	if r := project(b2.Recs); r.Approvals[0].Status() != "approved" {
		t.Fatalf("out-of-order decision: %+v", r.Approvals)
	}
}

func TestBudgetOverspend(t *testing.T) {
	r := project(streams()["ledger"].Recs)
	bs := Budgets(r, "g-ledger")
	if len(bs) != 1 {
		t.Fatalf("budgets: %+v", bs)
	}
	s := bs[0]
	if s.Allocated != 20 || s.Spent != 24.99 || !s.Overspent || len(s.Lines) != 3 {
		t.Fatalf("summary: %+v", s)
	}
	if s.Lines[1].Overspent || !s.Lines[2].Overspent || fmt.Sprintf("%.2f", s.Lines[2].Balance) != "-4.99" {
		t.Fatalf("lines: %+v", s.Lines)
	}
	// Warrant: max_calls=1, two allowed calls without goal_id → second overspends,
	// and the lines are visible from the token's goal.
	w := project(streams()["warrant"].Recs)
	wb := Budgets(w, "g-w")
	if len(wb) != 1 || len(wb[0].Lines) != 3 || !wb[0].Overspent || wb[0].Balance != -1 {
		t.Fatalf("warrant budget: %+v", wb)
	}
	// No allocation → charges are not flagged as overspend.
	b := testfix.New()
	b.Add("ledger", "ledger.budget.charged", "g", A("alice"), map[string]any{"resource": "tokens", "amount": 100})
	if bs := Budgets(project(b.Recs), "g"); bs[0].Overspent {
		t.Fatal("unbudgeted charge flagged")
	}
}

// randomStream generates records over a small id space so ops collide a lot.
func randomStream(rng *rand.Rand, n int) []store.Record {
	b := testfix.New()
	chains := []string{"ledger", "gate", "warrant", "harbour", "proof"}
	pick := func(xs ...string) string { return xs[rng.Intn(len(xs))] }
	for i := 0; i < n; i++ {
		c := pick(chains...)
		g := pick("g1", "g2", "g3", "")
		act := map[string]any{"tool": "t", "n": rng.Intn(3)}
		actors := A(pick("alice", "bob"), pick("a1", "a2", "svc:s1"))
		switch rng.Intn(16) {
		case 0:
			b.Add(c, "ledger.goal.created", g, actors, map[string]any{"title": pick("x", "y")})
		case 1:
			b.Add(c, "ledger.goal.status", g, actors, map[string]any{"status": pick("open", "done", "failed")})
		case 2:
			b.Add(c, "ledger.step.planned", g, actors, map[string]any{"step_no": rng.Intn(3), "description": pick("d1", "d2")})
		case 3:
			b.Add(c, "ledger.action.attempted", g, actors, map[string]any{"attempt_id": pick("at1", "at2", "at3"), "step_no": rng.Intn(3), "tool": pick("t1", "t2"), "action": act})
		case 4:
			b.Add(c, "ledger.action.completed", g, actors, map[string]any{"attempt_id": pick("at1", "at2", "at3"), "outcome": pick("ok", "failed")})
		case 5:
			b.Add(c, "ledger.verification.recorded", g, actors, map[string]any{"attempt_id": pick("at1", "at2", ""), "verifier": "v", "passed": rng.Intn(2) == 0})
		case 6:
			b.Add(c, "ledger.approval.requested", g, actors, map[string]any{"request_id": pick("r1", "r2"), "action": act})
		case 7:
			b.Add(c, pick("ledger.approval.granted", "ledger.approval.denied"), g, actors, map[string]any{"request_id": pick("r1", "r2"), "action": act})
		case 8:
			b.Add(c, pick("ledger.budget.allocated", "ledger.budget.charged"), g, actors, map[string]any{"resource": pick("usd", "calls"), "amount": rng.Intn(10)})
		case 9:
			b.Add(c, "ledger.identity.asserted", "", actors, map[string]any{"operator_id": pick("a1", "a2"), "fact": "f", "value": rng.Intn(5)})
		case 10:
			b.Add(c, "ledger.memory.written", g, actors, map[string]any{"key": "k", "value": rng.Intn(5)})
		case 11:
			b.Add(c, "ledger.tool.registered", "", actors, map[string]any{"tool_id": pick("t1", "t2"), "name": pick("N1", "N2")})
		case 12:
			b.Add(c, "warrant.token.issued", g, actors, map[string]any{"token_id": pick("k1", "k2"), "subject": "a1", "max_calls": rng.Intn(3)})
		case 13:
			b.Add(c, pick("warrant.call.allowed", "warrant.call.denied"), "", actors, map[string]any{"token_id": pick("k1", "k2"), "tool": "t", "action_hash": pick("h1", "h2")})
		case 14:
			b.Add(c, pick("harbour.effect.intent", "harbour.effect.result"), g, actors, map[string]any{"effect_id": rng.Intn(3), "step": rng.Intn(3), "tool": "t", "status": pick("committed", "failed")})
		default:
			b.Add(c, pick("gate.run.started", "gate.stage.completed", "gate.run.decided"), g, actors, map[string]any{"run_id": pick("r1", "r2"), "stage": "s", "status": "pass", "decision": pick("pass", "block")})
		}
	}
	return b.Recs
}

// Property: incremental projection (per-chain cursors, random interleaving of chain
// batches, redelivered records) always equals a rebuild in global order.
func TestRebuildEqualsIncremental(t *testing.T) {
	for seed := int64(1); seed <= 150; seed++ {
		rng := rand.New(rand.NewSource(seed))
		recs := randomStream(rng, 5+rng.Intn(60))
		rebuild := project(recs)

		byChain := map[string][]store.Record{}
		var chains []string
		for _, r := range recs {
			if _, ok := byChain[r.Chain]; !ok {
				chains = append(chains, r.Chain)
			}
			byChain[r.Chain] = append(byChain[r.Chain], r)
		}
		m := NewModel()
		for {
			var open []string
			for _, c := range chains {
				if m.Cursor(c) < int64(len(byChain[c])) {
					open = append(open, c)
				}
			}
			if len(open) == 0 {
				break
			}
			c := open[rng.Intn(len(open))]
			cur := int(m.Cursor(c))
			n := 1 + rng.Intn(5)
			start := cur
			if cur > 0 && rng.Intn(4) == 0 {
				start = cur - 1 // redelivery
			}
			for i := start; i < cur+n && i < len(byChain[c]); i++ {
				m.Apply(byChain[c][i])
			}
		}
		if d := Diff(rebuild, m.Rows()); d != "" {
			t.Fatalf("seed %d: rebuild != incremental: %s", seed, d)
		}
	}
}

// TestGateStageSkippedNotCountedPassed ensures a skipped Gate stage is projected as a failed
// (not passed) verification row: it did not run, so it must not count toward "passed".
func TestGateStageSkippedNotCountedPassed(t *testing.T) {
	b := testfix.New()
	g := "g-gate-skip"
	b.Add("gate", "gate.run.started", g, A("alice", "coder"), map[string]any{"run_id": "run-skip", "repo": "acme/api", "base": "main", "head": "abc"})
	b.Add("gate", "gate.stage.completed", g, A("alice", "coder"), map[string]any{"run_id": "run-skip", "stage": "tests", "status": "skipped", "risk": 0, "findings": 0})

	rows := project(b.Recs)
	found := false
	for _, v := range rows.Verifications {
		if v.Verifier == "gate.tests" {
			found = true
			if v.Passed {
				t.Error("skipped gate stage projected as passed")
			}
		}
	}
	if !found {
		t.Fatal("skipped stage verification row not found")
	}
}
