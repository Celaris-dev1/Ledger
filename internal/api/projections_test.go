package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Celaris-dev1/Ledger/internal/projection"
	"github.com/Celaris-dev1/Ledger/internal/store"
	"github.com/Celaris-dev1/Ledger/internal/testfix"
)

// chainBackend adds Chains so the incident review can use it.
type chainBackend struct{ *memBackend }

func (c chainBackend) Chains(context.Context) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, r := range c.recs {
		if !seen[r.Chain] {
			seen[r.Chain] = true
			out = append(out, r.Chain)
		}
	}
	return out, nil
}

func TestProjectionAndIncidentAPI(t *testing.T) {
	b := testfix.MultiProduct()
	m := projection.NewModel()
	for _, r := range b.Recs {
		m.Apply(r)
	}
	be := chainBackend{&memBackend{recs: append([]store.Record(nil), b.Recs...)}}
	var appended int
	h := (&Server{Store: be, Projections: projection.ModelReader{M: m}, OnAppend: func(*store.Record) { appended++ }}).Handler()

	w := do(t, h, "GET", "/v1/goals", "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"goal-incident-7"`) {
		t.Fatalf("goals: %d %s", w.Code, w.Body)
	}
	w = do(t, h, "GET", "/v1/goals/goal-incident-7", "", "")
	var tree projection.GoalTree
	if err := json.Unmarshal(w.Body.Bytes(), &tree); err != nil || w.Code != 200 {
		t.Fatalf("tree: %d %s", w.Code, w.Body)
	}
	if tree.Goal.Status != "failed" || len(tree.Steps) != 2 || len(tree.Steps[0].Attempts) != 1 || tree.Steps[0].Attempts[0].Outcome != "committed" {
		t.Fatalf("tree: %s", w.Body)
	}
	if ev := tree.Steps[0].Attempts[0].Evidence; len(ev) != 2 || ev[0].Hash == "" || ev[0].Chain != "harbour" {
		t.Fatalf("evidence: %+v", ev)
	}
	if w := do(t, h, "GET", "/v1/goals/nope", "", ""); w.Code != 404 {
		t.Fatalf("missing goal: %d", w.Code)
	}
	// replay route still wins for /replay
	if w := do(t, h, "GET", "/v1/goals/goal-incident-7/replay", "", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"records"`) {
		t.Fatalf("replay: %d", w.Code)
	}
	w = do(t, h, "GET", "/v1/approvals?status=denied", "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"ah-push"`) || strings.Contains(w.Body.String(), `"ah-get"`) {
		t.Fatalf("approvals: %s", w.Body)
	}
	if w := do(t, h, "GET", "/v1/approvals?status=bogus", "", ""); w.Code != 400 {
		t.Fatalf("bad status: %d", w.Code)
	}
	w = do(t, h, "GET", "/v1/budgets/goal-incident-7", "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"calls:tok-1"`) {
		t.Fatalf("budgets: %s", w.Body)
	}
	w = do(t, h, "GET", "/v1/incidents/goal-incident-7", "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"all_chains_intact":true`) {
		t.Fatalf("incident: %d %s", w.Code, w.Body)
	}
	w = do(t, h, "GET", "/v1/incidents/goal-incident-7?format=html", "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "&lt;script&gt;") || w.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("incident html: %d", w.Code)
	}
	w = do(t, h, "GET", "/v1/incidents/goal-incident-7?format=md", "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "# Incident review") {
		t.Fatalf("incident md: %d", w.Code)
	}
	if w := do(t, h, "GET", "/v1/incidents/nope", "", ""); w.Code != 404 {
		t.Fatalf("incident missing: %d", w.Code)
	}
	if w := do(t, h, "GET", "/v1/projections/vocabulary", "", ""); !strings.Contains(w.Body.String(), "ledger.approval.granted") {
		t.Fatal("vocabulary")
	}
	body := `{"chain":"ledger","type":"ledger.goal.created","goal_id":"g2","actor_chain":[{"kind":"human","id":"alice"}],"payload":{}}`
	if w := do(t, h, "POST", "/v1/records", body, ""); w.Code != 201 || appended != 1 {
		t.Fatalf("OnAppend not called: %d %d", w.Code, appended)
	}

	// Without projections the routes degrade to 503, not a crash.
	h = (&Server{Store: &memBackend{}}).Handler()
	if w := do(t, h, "GET", "/v1/goals", "", ""); w.Code != 503 {
		t.Fatalf("no projections: %d", w.Code)
	}
	if w := do(t, h, "GET", "/v1/incidents/x", "", ""); w.Code != 503 {
		t.Fatalf("no chains: %d", w.Code)
	}
}
