// Package testfix builds deterministic, correctly hash-chained record streams for tests.
package testfix

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/canon"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

// Builder appends records to in-memory chains with fixed ids and timestamps.
type Builder struct {
	T0    time.Time
	tick  int
	heads map[string]store.Record
	Recs  []store.Record
}

func New() *Builder {
	return &Builder{T0: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC), heads: map[string]store.Record{}}
}

// Actors builds an actor chain: first is the human, rest are agents ("svc:" prefix = service).
func Actors(human string, rest ...string) []store.Actor {
	out := []store.Actor{{Kind: "human", ID: human}}
	for _, r := range rest {
		if len(r) > 4 && r[:4] == "svc:" {
			out = append(out, store.Actor{Kind: "service", ID: r[4:]})
		} else {
			out = append(out, store.Actor{Kind: "agent", ID: r})
		}
	}
	return out
}

// Add appends one record. payload may be a map or a JSON string.
func (b *Builder) Add(chain, typ, goal string, actors []store.Actor, payload any) store.Record {
	var pl []byte
	switch v := payload.(type) {
	case string:
		pl = []byte(v)
	case nil:
		pl = []byte(`{}`)
	default:
		pl, _ = json.Marshal(v)
	}
	plc, err := canon.CanonicalBytes(pl)
	if err != nil {
		panic(err)
	}
	ac, _ := json.Marshal(actors)
	acc, _ := canon.CanonicalBytes(ac)
	head := b.heads[chain]
	b.tick++
	h := sha256.Sum256([]byte(fmt.Sprintf("%s/%d/%d", chain, head.Seq+1, b.tick)))
	r := store.Record{
		ID:         fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16]),
		Chain:      chain,
		Seq:        head.Seq + 1,
		Type:       typ,
		GoalID:     goal,
		ActorChain: acc,
		Payload:    plc,
		CreatedAt:  b.T0.Add(time.Duration(b.tick) * time.Second),
		PrevHash:   head.Hash,
	}
	if r.Hash, err = store.ComputeHash(&r); err != nil {
		panic(err)
	}
	b.heads[chain] = r
	b.Recs = append(b.Recs, r)
	return r
}

// Chain returns one chain's records in seq order.
func (b *Builder) Chain(name string) []store.Record {
	var out []store.Record
	for _, r := range b.Recs {
		if r.Chain == name {
			out = append(out, r)
		}
	}
	return out
}

// Chains lists chain names in first-appearance order.
func (b *Builder) Chains() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range b.Recs {
		if !seen[r.Chain] {
			seen[r.Chain] = true
			out = append(out, r.Chain)
		}
	}
	return out
}

// Request converts a record back into the append request that would produce it.
func Request(r store.Record) store.AppendRequest {
	var actors []store.Actor
	_ = json.Unmarshal(r.ActorChain, &actors)
	return store.AppendRequest{Chain: r.Chain, Type: r.Type, GoalID: r.GoalID, ActorChain: actors, PolicyVersion: r.PolicyVersion, Payload: r.Payload}
}

// MultiProduct is the realistic incident fixture: Warrant issues a token for a goal,
// Harbour runs the goal with effect intents/results (one committed, one not), Gate checks
// the resulting change (run linked via payload run_id), Proof captures a source page
// (its goal_id is its own run id, linked from the Harbour effect args), plus ledger.*
// approvals and a Warrant call without goal_id linked by token_id.
func MultiProduct() *Builder {
	b := New()
	g := "goal-incident-7"
	b.Add("harbour", "harbour.goal.transition", g, Actors("alice", "planner-agent"), map[string]any{"from": "", "to": "proposed", "name": "ship-fix", "goal_name": "ship-fix"})
	b.Add("warrant", "warrant.token.issued", g, Actors("alice", "planner-agent"), map[string]any{"token_id": "tok-1", "subject": "planner-agent", "depth": 0, "max_depth": 2, "max_calls": 2, "scopes": []string{"repo:write", "http:get"}, "goal_id": g})
	b.Add("harbour", "harbour.goal.transition", g, Actors("alice", "planner-agent"), map[string]any{"from": "proposed", "to": "approved", "reason": "operator approved", "actor": "alice", "goal_name": "ship-fix"})
	b.Add("ledger", "ledger.approval.requested", g, Actors("alice", "planner-agent"), map[string]any{"request_id": "apr-1", "action": map[string]any{"tool": "git.push", "repo": "acme/api"}, "reason": "push fix"})
	b.Add("ledger", "ledger.approval.granted", g, Actors("alice"), map[string]any{"request_id": "apr-1", "action": map[string]any{"tool": "git.push", "repo": "acme/api"}})
	b.Add("harbour", "harbour.effect.intent", g, Actors("alice", "planner-agent", "svc:worker-1"), map[string]any{"effect_id": 1, "step": 1, "tool": "http.get", "idem_key": "k1", "args": map[string]any{"url": "https://docs.example.com/api", "proof_run_id": "proof-run-9"}, "goal_name": "ship-fix"})
	b.Add("warrant", "warrant.call.allowed", "", Actors("alice", "planner-agent"), map[string]any{"token_id": "tok-1", "depth": 0, "tool": "http.get", "resource": "https://docs.example.com/api", "action_hash": "ah-get", "reason": "scope http:get"})
	b.Add("proof", "proof.fetch.captured", "proof-run-9", Actors("alice", "svc:proof"), map[string]any{"capture_id": "cap-1", "run_id": "proof-run-9", "url": "https://docs.example.com/api", "fetched": true, "robots_allowed": true, "compliant": true, "content_sha256": "c0ffee"})
	b.Add("harbour", "harbour.effect.result", g, Actors("alice", "planner-agent", "svc:worker-1"), map[string]any{"effect_id": 1, "step": 1, "tool": "http.get", "idem_key": "k1", "status": "committed", "via": "run", "goal_name": "ship-fix"})
	b.Add("proof", "proof.manifest.signed", "proof-run-9", Actors("alice", "svc:proof"), map[string]any{"run_id": "proof-run-9", "seq": 1, "manifest_hash": "m-hash-1", "captures_root": "root-1", "capture_count": 1, "key_id": "k-proof"})
	b.Add("harbour", "harbour.effect.intent", g, Actors("alice", "planner-agent", "svc:worker-1"), map[string]any{"effect_id": 2, "step": 2, "tool": "git.push", "idem_key": "k2", "args": map[string]any{"repo": "acme/api", "gate_run_id": "gate-run-3"}, "goal_name": "ship-fix"})
	b.Add("gate", "gate.run.started", g, Actors("alice", "planner-agent"), map[string]any{"run_id": "gate-run-3", "repo": "acme/api", "base": "main", "head": "fix-1", "files": []string{"api.go"}})
	b.Add("gate", "gate.stage.completed", g, Actors("alice", "planner-agent"), map[string]any{"run_id": "gate-run-3", "stage": "tests", "status": "pass", "risk": 0.1, "findings": 0, "summary": "all tests pass"})
	b.Add("gate", "gate.stage.completed", g, Actors("alice", "planner-agent"), map[string]any{"run_id": "gate-run-3", "stage": "security", "status": "fail", "risk": 0.8, "findings": 2, "summary": "secret in diff <script>"})
	b.Add("gate", "gate.run.decided", g, Actors("alice", "planner-agent"), map[string]any{"run_id": "gate-run-3", "score": 0.42, "decision": "block"})
	b.Add("warrant", "warrant.call.denied", "", Actors("alice", "planner-agent"), map[string]any{"token_id": "tok-1", "depth": 0, "tool": "git.push", "resource": "acme/api", "action_hash": "ah-push", "reason": "blocked by gate"})
	b.Add("harbour", "harbour.effect.result", g, Actors("alice", "planner-agent", "svc:worker-1"), map[string]any{"effect_id": 2, "step": 2, "tool": "git.push", "idem_key": "k2", "status": "failed", "via": "run", "error": "denied", "goal_name": "ship-fix"})
	b.Add("harbour", "harbour.goal.transition", g, Actors("alice", "planner-agent"), map[string]any{"from": "running", "to": "failed", "reason": "push denied", "goal_name": "ship-fix"})
	// unrelated noise that must not be pulled in
	b.Add("harbour", "harbour.effect.intent", "other-goal", Actors("bob", "x"), map[string]any{"effect_id": 1, "step": 1, "tool": "http.get", "idem_key": "zz", "args": map[string]any{}})
	b.Add("bench", "bench.run.scored", "task-5", Actors("carol", "bench-agent"), map[string]any{"run_id": "bench-run-1", "task_id": "task-5", "passed": true})
	return b
}
