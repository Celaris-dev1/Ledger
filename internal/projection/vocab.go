// Package projection turns hash-chained records into the spec's domain tables
// (goals, goal_steps, action_attempts, verification_results, approval_requests,
// budget_ledger, identity_facts, memory_items, tools, operators).
//
// Design: Map(record) is a pure function that turns one record into a list of Ops.
// Every Op belongs to a "group" (the unit that is recomputed, e.g. one goal, one
// attempt, one approval request with its decisions, one budget line). A group's
// rows are a pure fold over all of its Ops sorted by record order key
// (created_at, chain, seq), so the result does not depend on the order in which
// chains were projected: incremental projection (per-chain cursors, any
// interleaving, duplicates) and a rebuild from scratch give identical rows.
//
// See Vocabulary for the documented, versioned ledger.* payload convention and
// ProductMappings for how gate.*, proof.*, warrant.*, harbour.* and bench.* map on.
package projection

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/canon"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

// Version is the projector version. Bump it whenever Map or a fold changes meaning;
// a stored projection with a different version is rebuilt automatically.
const Version = 1

// VocabEntry documents one ledger.* record type.
type VocabEntry struct {
	Type     string   `json:"type"`
	Since    int      `json:"since_version"`
	Required []string `json:"required"`
	Optional []string `json:"optional"`
	Projects string   `json:"projects"`
}

// Vocabulary is the ledger.* payload convention (version 1). Records keep their
// goal_id in the envelope; payload fields are listed here.
var Vocabulary = []VocabEntry{
	{"ledger.goal.created", 1, nil, []string{"title", "status"}, "goals"},
	{"ledger.goal.status", 1, []string{"status"}, []string{"reason"}, "goals.status"},
	{"ledger.step.planned", 1, []string{"step_no"}, []string{"description", "status"}, "goal_steps"},
	{"ledger.step.status", 1, []string{"step_no", "status"}, nil, "goal_steps.status"},
	{"ledger.tool.registered", 1, []string{"tool_id"}, []string{"name", "version", "description"}, "tools"},
	{"ledger.action.attempted", 1, []string{"attempt_id", "tool"}, []string{"step_no", "action", "action_hash", "arguments", "tool_version"}, "action_attempts (action_hash = sha256(canonical_json(action)))"},
	{"ledger.action.completed", 1, []string{"attempt_id", "outcome"}, []string{"result"}, "action_attempts.outcome"},
	{"ledger.verification.recorded", 1, []string{"verifier", "passed"}, []string{"attempt_id", "evidence"}, "verification_results"},
	{"ledger.approval.requested", 1, []string{"request_id", "action_hash|action"}, []string{"reason"}, "approval_requests"},
	{"ledger.approval.granted", 1, []string{"request_id", "action_hash|action"}, []string{"reason"}, "approval_requests.decision=approved (only if action_hash matches the request)"},
	{"ledger.approval.denied", 1, []string{"request_id", "action_hash|action"}, []string{"reason"}, "approval_requests.decision=denied (only if action_hash matches the request)"},
	{"ledger.budget.allocated", 1, []string{"resource", "amount"}, nil, "budget_ledger (+amount)"},
	{"ledger.budget.charged", 1, []string{"resource", "amount"}, nil, "budget_ledger (-amount, running balance, overspend flagged)"},
	{"ledger.identity.asserted", 1, []string{"operator_id", "fact"}, []string{"value", "operator_kind"}, "identity_facts"},
	{"ledger.memory.written", 1, []string{"key"}, []string{"value"}, "memory_items"},
}

// ProductMapping documents how an existing product record type is projected.
type ProductMapping struct {
	Type   string `json:"type"`
	MapsTo string `json:"maps_to"`
}

// ProductMappings lists every product record type from CONTRACTS.md (and gate serve).
var ProductMappings = []ProductMapping{
	{"gate.run.started", "action.attempted (attempt gate:<run_id>, tool gate, action={repo,base,head})"},
	{"gate.stage.completed", "verification.recorded (verifier gate.<stage>, attempt gate:<run_id>)"},
	{"gate.run.decided", "verification.recorded (verifier gate) + action.completed (outcome=decision)"},
	{"gate.run.enforced", "verification.recorded (verifier gate.enforced) + action.completed (outcome=decision)"},
	{"gate.policy.version.created", "memory.written (key gate.policy.<scope>)"},
	{"gate.admin.*", "evidence only (operators)"},
	{"proof.fetch.captured", "action.attempted+completed (attempt proof:<capture_id>, tool proof.fetch, action={url}) + verification.recorded (verifier proof.compliance)"},
	{"proof.manifest.signed", "verification.recorded (verifier proof.manifest, evidence=manifest hash)"},
	{"warrant.token.issued", "identity.asserted (subject holds token scopes) + budget.allocated (calls:<token_id> = max_calls)"},
	{"warrant.call.allowed", "approval.requested+granted (bound to payload action_hash, decided by warrant) + budget.charged (calls:<token_id>, 1)"},
	{"warrant.call.denied", "approval.requested+denied (bound to payload action_hash, decided by warrant)"},
	{"warrant.token.revoked", "identity.asserted (fact token.revoked)"},
	{"harbour.goal.transition", "goal.status (to), goal title from goal_name"},
	{"harbour.effect.intent", "step.planned (step) + action.attempted (attempt harbour:<goal>:<effect_id>, action={tool,args,idem_key})"},
	{"harbour.effect.result", "action.completed (outcome=status)"},
	{"bench.task.mined", "memory.written (key bench.task.<task_id>)"},
	{"bench.run.scored", "verification.recorded (verifier bench, passed)"},
}

// Op is one projection operation derived from a record.
type Op struct {
	ID       string         `json:"id"`    // record_id#n (stable, idempotent)
	Group    string         `json:"group"` // recompute unit
	Kind     string         `json:"kind"`
	Key      string         `json:"key"` // order key: created_at|chain|seq
	At       string         `json:"at"`
	RecordID string         `json:"record_id"`
	GoalID   string         `json:"goal_id,omitempty"`
	F        map[string]any `json:"f,omitempty"`
}

// OrderKey sorts records globally (lexicographic == chronological).
func OrderKey(r *store.Record) string {
	return fmt.Sprintf("%s|%s|%020d", r.CreatedAt.UTC().Format("2006-01-02T15:04:05.000000000Z"), r.Chain, r.Seq)
}

// ActionHash is the canonical action hash: sha256hex(canonical_json(action)).
func ActionHash(action any) string {
	b, err := canon.Marshal(action)
	if err != nil {
		return ""
	}
	c, err := canon.CanonicalBytes(b)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(c)
	return hex.EncodeToString(h[:])
}

// DetUUID derives a deterministic UUID from a name (rows get stable ids across rebuilds).
func DetUUID(name string) string {
	h := sha256.Sum256([]byte("ledger-projection/" + name))
	b := h[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

type payload map[string]any

func (p payload) s(k string) string {
	switch v := p[k].(type) {
	case nil:
		return ""
	case string:
		return v
	case json.Number:
		return v.String()
	case bool:
		return strconv.FormatBool(v)
	default:
		b, _ := canon.Marshal(v)
		return string(b)
	}
}

func (p payload) num(k string) (float64, bool) {
	switch v := p[k].(type) {
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(v, 64)
		return f, err == nil
	}
	return 0, false
}

func (p payload) b(k string) (bool, bool) {
	switch v := p[k].(type) {
	case bool:
		return v, true
	case string:
		switch strings.ToLower(v) {
		case "true", "pass", "passed", "ok", "allow", "allowed", "approve", "approved":
			return true, true
		case "false", "fail", "failed", "deny", "denied", "block", "blocked", "reject":
			return false, true
		}
	}
	return false, false
}

type mapper struct {
	rec   *store.Record
	key   string
	at    string
	ops   []Op
	p     payload
	human string
	last  store.Actor
}

func (m *mapper) add(kind, group string, f map[string]any) {
	m.addGoal(kind, group, m.rec.GoalID, f)
}

func (m *mapper) addGoal(kind, group, goal string, f map[string]any) {
	m.ops = append(m.ops, Op{ID: fmt.Sprintf("%s#%d", m.rec.ID, len(m.ops)), Group: group, Kind: kind, Key: m.key, At: m.at,
		RecordID: m.rec.ID, GoalID: goal, F: f})
}

func (m *mapper) operator(id, kind string) {
	if id == "" {
		return
	}
	f := map[string]any{}
	if kind != "" {
		f["kind"] = kind
	}
	m.add("operator", "operator:"+id, f)
}

func (m *mapper) tool(id string, f map[string]any) {
	if id == "" {
		return
	}
	if f == nil {
		f = map[string]any{}
	}
	m.add("tool", "tool:"+id, f)
}

func (m *mapper) step(no int, f map[string]any) {
	if m.rec.GoalID == "" {
		return
	}
	m.add("step", fmt.Sprintf("step:%s/%d", m.rec.GoalID, no), withNo(f, no))
}

func withNo(f map[string]any, no int) map[string]any {
	if f == nil {
		f = map[string]any{}
	}
	f["step_no"] = no
	return f
}

// attempt emits the attempt op (plus stubs for its step and tool so FKs always resolve).
func (m *mapper) attempt(id string, stepNo *int, tool string, action any, actionHash string, args any) {
	if actionHash == "" && action != nil {
		actionHash = ActionHash(action)
	}
	f := map[string]any{"attempt_id": id, "tool": tool, "action_hash": actionHash, "policy_version": m.rec.PolicyVersion}
	if args != nil {
		f["arguments"] = args
	}
	if stepNo != nil && m.rec.GoalID != "" {
		f["step_no"] = *stepNo
		m.step(*stepNo, nil)
	}
	m.tool(tool, nil)
	m.add("attempt", "attempt:"+id, f)
}

func (m *mapper) result(id, outcome string, detail any) {
	f := map[string]any{"attempt_id": id, "outcome": outcome}
	if detail != nil {
		f["result"] = detail
	}
	m.add("attempt_result", "attempt:"+id, f)
}

func (m *mapper) verification(attemptID, verifier string, passed bool, evidence any) {
	id := DetUUID(fmt.Sprintf("verification/%s/%d", m.rec.ID, len(m.ops)))
	if attemptID != "" {
		m.add("attempt_touch", "attempt:"+attemptID, map[string]any{"attempt_id": attemptID})
	}
	m.add("verification", "row:"+id, map[string]any{"row_id": id, "attempt_id": attemptID, "verifier": verifier, "passed": passed, "evidence": evidence})
}

func (m *mapper) approvalRequest(reqID, hash, by, reason string) {
	m.operator(by, "")
	m.add("approval_request", "approval:"+reqID, map[string]any{"request_id": reqID, "action_hash": hash, "requested_by": by, "reason": reason})
}

func (m *mapper) approvalDecision(reqID, hash, decision, by, reason string) {
	m.operator(by, "")
	m.add("approval_decision", "approval:"+reqID, map[string]any{"request_id": reqID, "action_hash": hash, "decision": decision, "decided_by": by, "reason": reason, "row_id": DetUUID("decision/" + m.rec.ID + "/" + reqID)})
}

// budget adds a budget line. Lines in one group share a running balance; group ""
// means per (goal, resource). Warrant token budgets use a per-token group because
// allowed calls often carry no goal_id while the issuing record does.
func (m *mapper) budget(resource string, delta float64, kind, group string) {
	m.operator(m.last.ID, m.last.Kind)
	if group == "" {
		group = "budget:" + m.rec.GoalID + "/" + resource
	}
	m.add("budget", group, map[string]any{"resource": resource, "delta": delta, "entry_kind": kind,
		"operator_id": m.last.ID, "row_id": DetUUID(fmt.Sprintf("budget/%s/%d", m.rec.ID, len(m.ops)))})
}

func (m *mapper) identity(operatorID, kind, fact string, value any) {
	operatorID = firstNonEmpty(operatorID, "unknown")
	m.operator(operatorID, kind)
	id := DetUUID(fmt.Sprintf("identity/%s/%d", m.rec.ID, len(m.ops)))
	m.add("identity", "row:"+id, map[string]any{"row_id": id, "operator_id": operatorID, "fact": fact, "value": value, "asserted_by": m.last.ID})
}

func (m *mapper) memory(key string, value any) {
	id := DetUUID(fmt.Sprintf("memory/%s/%d", m.rec.ID, len(m.ops)))
	m.add("memory", "row:"+id, map[string]any{"row_id": id, "key": key, "value": value, "operator_id": m.last.ID})
}

func (m *mapper) actionOrHash() (any, string) {
	a := m.p["action"]
	h := m.p.s("action_hash")
	if a != nil {
		if computed := ActionHash(a); computed != "" {
			h = computed // the canonical action wins over a claimed hash
		}
	}
	return a, h
}

func intPtr(p payload, k string) *int {
	if f, ok := p.num(k); ok {
		n := int(f)
		return &n
	}
	return nil
}

// Map turns one record into projection ops. mapped=false means the type is not in
// the vocabulary (the record still contributes its operators and goal).
func Map(rec store.Record) (ops []Op, mapped bool) {
	m := &mapper{rec: &rec, key: OrderKey(&rec), at: rec.CreatedAt.UTC().Format(time.RFC3339Nano)}
	var actors []store.Actor
	_ = json.Unmarshal(rec.ActorChain, &actors)
	if v, err := canon.Normalize(rec.Payload); err == nil {
		m.p, _ = v.(map[string]any)
	}
	if m.p == nil {
		m.p = payload{}
	}
	for _, a := range actors {
		f := map[string]any{"kind": a.Kind, "explicit": true}
		if a.Model != "" {
			f["model"] = a.Model
		}
		if a.ModelVersion != "" {
			f["model_version"] = a.ModelVersion
		}
		if a.ID != "" {
			m.add("operator", "operator:"+a.ID, f)
		}
	}
	if len(actors) > 0 {
		m.human, m.last = actors[0].ID, actors[len(actors)-1]
	}
	if rec.GoalID != "" {
		m.add("goal", "goal:"+rec.GoalID, map[string]any{"human": m.human})
	}
	mapped = m.mapType()
	// Normalise through JSON so in-memory and stored ops fold identically.
	b, _ := json.Marshal(m.ops)
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out []Op
	_ = dec.Decode(&out)
	// Postgres text/jsonb columns cannot hold U+0000, which a stored payload may contain; left
	// in, one such record failed every projector run on its chain. Replace it with U+FFFD.
	for i := range out {
		out[i].Group, out[i].Key, out[i].GoalID = noNUL(out[i].Group), noNUL(out[i].Key), noNUL(out[i].GoalID)
		if out[i].F != nil {
			out[i].F = scrubNUL(out[i].F).(map[string]any)
		}
	}
	return out, mapped
}

func noNUL(s string) string { return strings.ReplaceAll(s, "\x00", "\uFFFD") }

func scrubNUL(v any) any {
	switch t := v.(type) {
	case string:
		return noNUL(t)
	case []any:
		for i := range t {
			t[i] = scrubNUL(t[i])
		}
		return t
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[noNUL(k)] = scrubNUL(x)
		}
		return out
	}
	return v
}

func (m *mapper) mapType() bool {
	p, r := m.p, m.rec
	t := r.Type
	switch {
	case t == "ledger.goal.created":
		m.add("goal", "goal:"+r.GoalID, map[string]any{"title": p.s("title"), "status": firstNonEmpty(p.s("status"), "open")})
	case t == "ledger.goal.status":
		m.add("goal", "goal:"+r.GoalID, map[string]any{"status": p.s("status")})
	case t == "ledger.step.planned" || t == "ledger.step.status":
		no := intPtr(p, "step_no")
		if no == nil {
			return false
		}
		f := map[string]any{"status": p.s("status")}
		if t == "ledger.step.planned" {
			f["description"], f["planned"] = p.s("description"), true
			if f["status"] == "" {
				f["status"] = "planned"
			}
		}
		m.step(*no, f)
	case t == "ledger.tool.registered":
		m.tool(p.s("tool_id"), map[string]any{"name": p.s("name"), "version": p.s("version"), "description": p.s("description")})
	case t == "ledger.action.attempted":
		a, h := m.actionOrHash()
		m.attempt(p.s("attempt_id"), intPtr(p, "step_no"), p.s("tool"), nil, h, firstNonNil(p["arguments"], a))
	case t == "ledger.action.completed":
		m.result(p.s("attempt_id"), p.s("outcome"), p["result"])
	case t == "ledger.verification.recorded":
		passed, _ := p.b("passed")
		m.verification(p.s("attempt_id"), p.s("verifier"), passed, p["evidence"])
	case t == "ledger.approval.requested":
		_, h := m.actionOrHash()
		m.approvalRequest(p.s("request_id"), h, m.last.ID, p.s("reason"))
	case t == "ledger.approval.granted" || t == "ledger.approval.denied":
		_, h := m.actionOrHash()
		d := "approved"
		if t == "ledger.approval.denied" {
			d = "denied"
		}
		m.approvalDecision(p.s("request_id"), h, d, m.last.ID, p.s("reason"))
	case t == "ledger.budget.allocated" || t == "ledger.budget.charged":
		amt, ok := p.num("amount")
		if !ok || p.s("resource") == "" {
			return false
		}
		if t == "ledger.budget.charged" {
			m.budget(p.s("resource"), -amt, "charge", "")
		} else {
			m.budget(p.s("resource"), amt, "allocation", "")
		}
	case t == "ledger.identity.asserted":
		m.identity(p.s("operator_id"), p.s("operator_kind"), p.s("fact"), p["value"])
	case t == "ledger.memory.written":
		m.memory(p.s("key"), p["value"])

	// ---- Gate
	case t == "gate.run.started":
		m.attempt("gate:"+p.s("run_id"), nil, "gate", map[string]any{"tool": "gate", "repo": p["repo"], "base": p["base"], "head": p["head"]}, "", map[string]any{"repo": p["repo"], "base": p["base"], "head": p["head"], "files": p["files"]})
	case t == "gate.stage.completed":
		passed := !strings.EqualFold(p.s("status"), "fail") && !strings.EqualFold(p.s("status"), "error")
		m.verification("gate:"+p.s("run_id"), "gate."+p.s("stage"), passed, map[string]any{"status": p["status"], "risk": p["risk"], "findings": p["findings"], "summary": p["summary"]})
	case t == "gate.run.decided" || t == "gate.run.enforced":
		dec := p.s("decision")
		v := "gate"
		if t == "gate.run.enforced" {
			v = "gate.enforced"
		}
		m.verification("gate:"+p.s("run_id"), v, gateDecisionPass(dec), map[string]any{"decision": dec, "score": p["score"], "policy_applied": p["policy_applied"]})
		m.result("gate:"+p.s("run_id"), dec, nil)
	case t == "gate.policy.version.created":
		m.memory("gate.policy."+firstNonEmpty(p.s("scope"), "default"), map[string]any(p))
	case strings.HasPrefix(t, "gate.admin."):
		return true

	// ---- Proof
	case t == "proof.fetch.captured":
		id := "proof:" + p.s("capture_id")
		m.attempt(id, nil, "proof.fetch", map[string]any{"tool": "proof.fetch", "url": p["url"]}, "", map[string]any{"url": p["url"]})
		outcome := "captured"
		if fetched, ok := p.b("fetched"); ok && !fetched {
			outcome = "not_fetched"
		}
		m.result(id, outcome, map[string]any{"content_sha256": p["content_sha256"]})
		compliant, _ := p.b("compliant")
		m.verification(id, "proof.compliance", compliant, map[string]any{"robots_allowed": p["robots_allowed"], "violations": p["violations"]})
	case t == "proof.manifest.signed":
		m.verification("", "proof.manifest", true, map[string]any{"manifest_hash": p["manifest_hash"], "captures_root": p["captures_root"], "capture_count": p["capture_count"], "key_id": p["key_id"]})

	// ---- Warrant
	case t == "warrant.token.issued":
		m.identity(p.s("subject"), "agent", "warrant.token", map[string]any{"token_id": p["token_id"], "parent_id": p["parent_id"], "scopes": p["scopes"], "depth": p["depth"], "expires": p["expires"]})
		if mc, ok := p.num("max_calls"); ok && mc > 0 {
			m.budget("calls:"+p.s("token_id"), mc, "allocation", "budget:token/"+p.s("token_id"))
		}
	case t == "warrant.call.allowed" || t == "warrant.call.denied":
		reqID := "warrant:" + r.ID
		h := p.s("action_hash")
		if h == "" {
			h = ActionHash(map[string]any{"tool": p["tool"], "resource": p["resource"], "action": p["action"]})
		}
		m.approvalRequest(reqID, h, m.last.ID, p.s("tool")+" "+p.s("resource"))
		d := "approved"
		if t == "warrant.call.denied" {
			d = "denied"
		}
		m.operator("warrant", "service")
		m.approvalDecision(reqID, h, d, "warrant", p.s("reason"))
		if d == "approved" {
			m.budget("calls:"+p.s("token_id"), -1, "charge", "budget:token/"+p.s("token_id"))
		}
	case t == "warrant.token.revoked":
		m.identity(firstNonEmpty(m.last.ID, "unknown"), "", "warrant.token.revoked", map[string]any{"token_id": p["token_id"], "reason": p["reason"], "revoked_by": p["revoked_by"]})

	// ---- Harbour
	case t == "harbour.goal.transition":
		m.add("goal", "goal:"+r.GoalID, map[string]any{"title": p.s("goal_name"), "status": p.s("to")})
	case t == "harbour.effect.intent":
		id := "harbour:" + r.GoalID + ":" + p.s("effect_id")
		step := intPtr(p, "step")
		if step != nil {
			m.step(*step, map[string]any{"description": p.s("tool"), "planned": true, "status": "planned"})
		}
		m.attempt(id, step, p.s("tool"), map[string]any{"tool": p["tool"], "args": p["args"], "idem_key": p["idem_key"]}, "", p["args"])
	case t == "harbour.effect.result":
		id := "harbour:" + r.GoalID + ":" + p.s("effect_id")
		m.result(id, p.s("status"), map[string]any{"via": p["via"], "error": p["error"]})
		if step := intPtr(p, "step"); step != nil && strings.EqualFold(p.s("status"), "committed") {
			m.step(*step, map[string]any{"status": "done"})
		}

	// ---- Bench
	case t == "bench.task.mined":
		m.memory("bench.task."+p.s("task_id"), map[string]any(p))
	case t == "bench.run.scored":
		passed, _ := p.b("passed")
		m.verification("", "bench", passed, map[string]any{"run_id": p["run_id"], "task_id": p["task_id"], "failure_mode": p["failure_mode"], "risk_score": p["risk_score"]})
	default:
		return false
	}
	return true
}

func gateDecisionPass(d string) bool {
	switch strings.ToLower(d) {
	case "pass", "allow", "approve", "approved", "merge", "auto_merge", "auto-merge":
		return true
	}
	return false
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func firstNonNil(v ...any) any {
	for _, x := range v {
		if x != nil {
			return x
		}
	}
	return nil
}

// sortOps orders ops by (key, id) — the only order folds ever see.
func sortOps(ops []Op) {
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].Key != ops[j].Key {
			return ops[i].Key < ops[j].Key
		}
		return opIndexLess(ops[i].ID, ops[j].ID)
	})
}

func opIndexLess(a, b string) bool {
	ai, bi := strings.LastIndexByte(a, '#'), strings.LastIndexByte(b, '#')
	if ai > 0 && bi > 0 && a[:ai] == b[:bi] {
		x, _ := strconv.Atoi(a[ai+1:])
		y, _ := strconv.Atoi(b[bi+1:])
		return x < y
	}
	return a < b
}
