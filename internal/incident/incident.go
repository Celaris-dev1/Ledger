// Package incident builds a cross-product incident review for one goal: it joins
// every chain (gate, proof, warrant, harbour, bench, ledger, ...) by goal_id plus
// explicit cross-references in payloads (run ids, token ids, capture/manifest ids,
// action hashes, request/attempt ids) into one ordered narrative, and reports who
// authorised what, what ran, what was verified, which effects committed, and the
// hash-chain verification status of every source chain.
package incident

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/store"
)

// Source is what the builder needs from storage (*store.Store satisfies it).
type Source interface {
	Chains(ctx context.Context) ([]string, error)
	ChainRecords(ctx context.Context, chain string) ([]store.Record, error)
	Verify(ctx context.Context, chain string) (store.VerifyResult, error)
}

// Entry is one narrative line.
type Entry struct {
	At       time.Time `json:"at"`
	Chain    string    `json:"chain"`
	Seq      int64     `json:"seq"`
	Type     string    `json:"type"`
	RecordID string    `json:"record_id"`
	Hash     string    `json:"hash"`
	GoalID   string    `json:"goal_id,omitempty"`
	Who      string    `json:"who"`
	Human    string    `json:"originating_human"`
	Category string    `json:"category"` // authorised|denied|ran|verified|effect|state|other
	Summary  string    `json:"summary"`
	LinkedBy string    `json:"linked_by"` // "goal_id" or "<ref>=<value>"
}

// Authorisation is who authorised (or refused) what.
type Authorisation struct {
	At       time.Time `json:"at"`
	Who      string    `json:"who"`
	Decision string    `json:"decision"` // granted|denied|revoked|requested|approved-goal
	What     string    `json:"what"`
	Source   string    `json:"source"`
	RecordID string    `json:"record_id"`
}

// Verification is one check result.
type Verification struct {
	At       time.Time `json:"at"`
	Verifier string    `json:"verifier"`
	Passed   bool      `json:"passed"`
	Detail   string    `json:"detail"`
	Source   string    `json:"source"`
	RecordID string    `json:"record_id"`
}

// Effect is a side effect (two-phase: intent then result).
type Effect struct {
	ID             string `json:"id"`
	Tool           string `json:"tool"`
	Status         string `json:"status"` // committed|failed|...|not committed (intent only)
	Committed      bool   `json:"committed"`
	IntentRecordID string `json:"intent_record_id"`
	ResultRecordID string `json:"result_record_id,omitempty"`
}

// ChainStatus is the verification status of one source chain.
type ChainStatus struct {
	Chain    string `json:"chain"`
	OK       bool   `json:"ok"`
	Length   int    `json:"length"`
	Head     string `json:"head"`
	BrokenAt *int64 `json:"broken_at"`
	Reason   string `json:"reason,omitempty"`
	Records  int    `json:"records_in_incident"`
}

// Report is the incident review (JSON form).
type Report struct {
	GoalID         string          `json:"goal_id"`
	GeneratedAt    time.Time       `json:"generated_at"`
	Summary        Summary         `json:"summary"`
	Chains         []ChainStatus   `json:"chains"`
	Authorisations []Authorisation `json:"authorisations"`
	Ran            []Entry         `json:"ran"`
	Verifications  []Verification  `json:"verifications"`
	Effects        []Effect        `json:"effects"`
	Narrative      []Entry         `json:"narrative"`
}

// Summary is the headline.
type Summary struct {
	Records          int      `json:"records"`
	Chains           int      `json:"chains"`
	AllChainsIntact  bool     `json:"all_chains_intact"`
	Humans           []string `json:"originating_humans"`
	FailedChecks     int      `json:"failed_verifications"`
	Denials          int      `json:"denials"`
	EffectsCommitted int      `json:"effects_committed"`
	EffectsNot       int      `json:"effects_not_committed"`
	Headline         string   `json:"headline"`
}

// refClass groups payload keys that name the same kind of identifier.
func refClass(key string) string {
	switch key {
	case "token_id", "parent_id":
		return "token_id"
	case "capture_id", "manifest_hash", "action_hash", "task_id", "request_id", "attempt_id":
		return key
	}
	if key == "run_id" || strings.HasSuffix(key, "_run_id") {
		return "run_id"
	}
	return ""
}

type ref struct{ class, value string }

func decode(raw []byte) map[string]any {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	_ = dec.Decode(&m)
	if m == nil {
		m = map[string]any{}
	}
	return m
}

func str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case json.Number:
		return x.String()
	case bool:
		return strconv.FormatBool(x)
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

// refsOf collects cross-reference identifiers from a payload (recursively).
func refsOf(v any, out map[ref]bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if c := refClass(k); c != "" {
				if s := str(val); s != "" && !strings.HasPrefix(s, "{") && !strings.HasPrefix(s, "[") {
					out[ref{c, s}] = true
				}
			}
			refsOf(val, out)
		}
	case []any:
		for _, e := range x {
			refsOf(e, out)
		}
	}
}

type item struct {
	rec     store.Record
	p       map[string]any
	refs    map[ref]bool
	linked  string
	actors  []store.Actor
	include bool
}

// Build assembles the incident review for goalID.
func Build(ctx context.Context, src Source, goalID string) (*Report, error) {
	chains, err := src.Chains(ctx)
	if err != nil {
		return nil, err
	}
	var items []*item
	for _, c := range chains {
		recs, err := src.ChainRecords(ctx, c)
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			it := &item{rec: r, p: decode(r.Payload), refs: map[ref]bool{}}
			refsOf(it.p, it.refs)
			_ = json.Unmarshal(r.ActorChain, &it.actors)
			if r.GoalID == goalID {
				it.include, it.linked = true, "goal_id"
			}
			items = append(items, it)
		}
	}
	// Fixpoint over explicit cross-references (bounded).
	for round := 0; round < 6; round++ {
		known := map[ref]bool{}
		for _, it := range items {
			if it.include {
				for rf := range it.refs {
					known[rf] = true
				}
			}
		}
		changed := false
		for _, it := range items {
			if it.include {
				continue
			}
			for rf := range it.refs {
				if known[rf] {
					it.include, it.linked, changed = true, rf.class+"="+rf.value, true
					break
				}
			}
			// A product that uses its run/task id as goal_id (Proof, Bench).
			if !it.include && it.rec.GoalID != "" && (known[ref{"run_id", it.rec.GoalID}] || known[ref{"task_id", it.rec.GoalID}]) {
				it.include, it.linked, changed = true, "run_id="+it.rec.GoalID, true
			}
		}
		if !changed {
			break
		}
	}
	var sel []*item
	for _, it := range items {
		if it.include {
			sel = append(sel, it)
		}
	}
	if len(sel) == 0 {
		return nil, nil
	}
	sort.Slice(sel, func(i, j int) bool {
		a, b := sel[i].rec, sel[j].rec
		if !a.CreatedAt.Equal(b.CreatedAt) {
			return a.CreatedAt.Before(b.CreatedAt)
		}
		if a.Chain != b.Chain {
			return a.Chain < b.Chain
		}
		return a.Seq < b.Seq
	})
	rep := &Report{GoalID: goalID, GeneratedAt: time.Now().UTC(), Authorisations: []Authorisation{}, Ran: []Entry{}, Verifications: []Verification{}, Effects: []Effect{}}
	perChain := map[string]int{}
	humans := map[string]bool{}
	effects := map[string]*Effect{}
	var effectOrder []string
	for _, it := range sel {
		e := describe(it)
		rep.Narrative = append(rep.Narrative, e)
		perChain[e.Chain]++
		if e.Human != "" {
			humans[e.Human] = true
		}
		src := fmt.Sprintf("%s#%d", e.Chain, e.Seq)
		switch e.Category {
		case "authorised", "denied":
			rep.Authorisations = append(rep.Authorisations, Authorisation{At: e.At, Who: e.Who, Decision: authDecision(it), What: e.Summary, Source: src, RecordID: e.RecordID})
			if e.Category == "denied" {
				rep.Summary.Denials++
			}
		case "ran":
			rep.Ran = append(rep.Ran, e)
		case "verified":
			passed := verificationPassed(it)
			rep.Verifications = append(rep.Verifications, Verification{At: e.At, Verifier: verifierName(it), Passed: passed, Detail: e.Summary, Source: src, RecordID: e.RecordID})
			if !passed {
				rep.Summary.FailedChecks++
			}
		}
		// Effects: harbour two-phase commit and ledger.action.*.
		var key, tool, status string
		isIntent := false
		switch it.rec.Type {
		case "harbour.effect.intent", "harbour.effect.result":
			key, tool, status = "harbour:"+it.rec.GoalID+":"+str(it.p["effect_id"]), str(it.p["tool"]), str(it.p["status"])
			isIntent = it.rec.Type == "harbour.effect.intent"
		case "ledger.action.attempted", "ledger.action.completed":
			key, tool, status = "ledger:"+str(it.p["attempt_id"]), str(it.p["tool"]), str(it.p["outcome"])
			isIntent = it.rec.Type == "ledger.action.attempted"
		}
		if key != "" {
			ef := effects[key]
			if ef == nil {
				ef = &Effect{ID: key, Status: "not committed (intent only)"}
				effects[key] = ef
				effectOrder = append(effectOrder, key)
			}
			if tool != "" {
				ef.Tool = tool
			}
			if isIntent {
				ef.IntentRecordID = it.rec.ID
			} else {
				ef.ResultRecordID, ef.Status = it.rec.ID, status
				ef.Committed = committed(status)
			}
		}
	}
	for _, k := range effectOrder {
		ef := effects[k]
		if ef.IntentRecordID == "" && ef.ResultRecordID != "" {
			ef.IntentRecordID = "(no intent record)"
		}
		rep.Effects = append(rep.Effects, *ef)
		if ef.Committed {
			rep.Summary.EffectsCommitted++
		} else {
			rep.Summary.EffectsNot++
		}
	}
	names := make([]string, 0, len(perChain))
	for c := range perChain {
		names = append(names, c)
	}
	sort.Strings(names)
	rep.Summary.AllChainsIntact = true
	for _, c := range names {
		v, err := src.Verify(ctx, c)
		if err != nil {
			return nil, err
		}
		rep.Chains = append(rep.Chains, ChainStatus{Chain: c, OK: v.OK, Length: v.Length, Head: v.Head, BrokenAt: v.BrokenAt, Reason: v.Reason, Records: perChain[c]})
		if !v.OK {
			rep.Summary.AllChainsIntact = false
		}
	}
	for h := range humans {
		rep.Summary.Humans = append(rep.Summary.Humans, h)
	}
	sort.Strings(rep.Summary.Humans)
	rep.Summary.Records, rep.Summary.Chains = len(sel), len(names)
	integrity := "all source chains verify"
	if !rep.Summary.AllChainsIntact {
		integrity = "WARNING: at least one source chain FAILS verification"
	}
	rep.Summary.Headline = fmt.Sprintf("%d records across %d chains; %d authorisations (%d denied); %d verifications (%d failed); %d effects committed, %d not; %s.",
		len(sel), len(names), len(rep.Authorisations), rep.Summary.Denials, len(rep.Verifications), rep.Summary.FailedChecks,
		rep.Summary.EffectsCommitted, rep.Summary.EffectsNot, integrity)
	return rep, nil
}

func committed(s string) bool {
	switch strings.ToLower(s) {
	case "committed", "succeeded", "success", "ok", "done", "completed":
		return true
	}
	return false
}

func authDecision(it *item) string {
	switch it.rec.Type {
	case "warrant.token.issued":
		return "granted"
	case "warrant.call.allowed", "ledger.approval.granted":
		return "granted"
	case "warrant.call.denied", "ledger.approval.denied":
		return "denied"
	case "warrant.token.revoked":
		return "revoked"
	case "ledger.approval.requested":
		return "requested"
	case "harbour.goal.transition":
		return "approved-goal"
	}
	return ""
}

func verificationPassed(it *item) bool {
	p := it.p
	switch it.rec.Type {
	case "gate.stage.completed":
		s := strings.ToLower(str(p["status"]))
		return s != "fail" && s != "error"
	case "gate.run.decided", "gate.run.enforced":
		switch strings.ToLower(str(p["decision"])) {
		case "pass", "allow", "approve", "approved", "merge", "auto_merge", "auto-merge":
			return true
		}
		return false
	case "proof.manifest.signed":
		return true
	}
	return str(p["passed"]) == "true"
}

func verifierName(it *item) string {
	switch it.rec.Type {
	case "gate.stage.completed":
		return "gate." + str(it.p["stage"])
	case "gate.run.decided":
		return "gate"
	case "gate.run.enforced":
		return "gate (server enforced)"
	case "proof.manifest.signed":
		return "proof.manifest"
	case "bench.run.scored":
		return "bench"
	}
	return str(it.p["verifier"])
}

func who(actors []store.Actor) (string, string) {
	var parts []string
	for _, a := range actors {
		s := a.ID
		if a.Kind != "human" {
			s += " (" + a.Kind
			if a.Model != "" {
				s += ", " + a.Model
			}
			s += ")"
		}
		parts = append(parts, s)
	}
	human := ""
	if len(actors) > 0 {
		human = actors[0].ID
	}
	return strings.Join(parts, " → "), human
}

func describe(it *item) Entry {
	r, p := it.rec, it.p
	w, h := who(it.actors)
	e := Entry{At: r.CreatedAt, Chain: r.Chain, Seq: r.Seq, Type: r.Type, RecordID: r.ID, Hash: r.Hash, GoalID: r.GoalID, Who: w, Human: h, LinkedBy: it.linked, Category: "other"}
	s := func(k string) string { return str(p[k]) }
	switch r.Type {
	case "warrant.token.issued":
		e.Category, e.Summary = "authorised", fmt.Sprintf("Warrant token %s issued to %s: scopes %s, max_calls %s, depth %s/%s", s("token_id"), s("subject"), s("scopes"), s("max_calls"), s("depth"), s("max_depth"))
	case "warrant.call.allowed":
		e.Category, e.Summary = "authorised", fmt.Sprintf("Warrant allowed %s on %s with token %s (action %s): %s", s("tool"), s("resource"), s("token_id"), s("action_hash"), s("reason"))
	case "warrant.call.denied":
		e.Category, e.Summary = "denied", fmt.Sprintf("Warrant DENIED %s %s on %s with token %s: %s", s("action"), s("tool"), s("resource"), s("token_id"), s("reason"))
	case "warrant.token.revoked":
		e.Category, e.Summary = "denied", fmt.Sprintf("Warrant token %s revoked by %s: %s", s("token_id"), s("revoked_by"), s("reason"))
	case "ledger.approval.requested":
		e.Category, e.Summary = "authorised", fmt.Sprintf("Approval %s requested for action %s: %s", s("request_id"), actionRef(p), s("reason"))
	case "ledger.approval.granted":
		e.Category, e.Summary = "authorised", fmt.Sprintf("Approval %s GRANTED for action %s", s("request_id"), actionRef(p))
	case "ledger.approval.denied":
		e.Category, e.Summary = "denied", fmt.Sprintf("Approval %s DENIED for action %s: %s", s("request_id"), actionRef(p), s("reason"))
	case "harbour.goal.transition":
		e.Category, e.Summary = "state", fmt.Sprintf("Harbour goal %s: %s → %s %s", s("goal_name"), s("from"), s("to"), s("reason"))
		if s("to") == "approved" {
			e.Category = "authorised"
		}
	case "harbour.effect.intent":
		e.Category, e.Summary = "ran", fmt.Sprintf("Harbour intent: effect %s step %s will call %s (idempotency key %s) args %s", s("effect_id"), s("step"), s("tool"), s("idem_key"), s("args"))
	case "harbour.effect.result":
		e.Category, e.Summary = "effect", fmt.Sprintf("Harbour result: effect %s (%s) %s via %s %s", s("effect_id"), s("tool"), strings.ToUpper(s("status")), s("via"), s("error"))
	case "gate.run.started":
		e.Category, e.Summary = "ran", fmt.Sprintf("Gate run %s started on %s %s..%s", s("run_id"), s("repo"), s("base"), s("head"))
	case "gate.stage.completed":
		e.Category, e.Summary = "verified", fmt.Sprintf("Gate stage %s: %s (risk %s, %s findings) %s", s("stage"), s("status"), s("risk"), s("findings"), s("summary"))
	case "gate.run.decided", "gate.run.enforced":
		e.Category, e.Summary = "verified", fmt.Sprintf("Gate run %s decision %s (score %s)", s("run_id"), strings.ToUpper(s("decision")), s("score"))
	case "gate.policy.version.created":
		e.Category, e.Summary = "state", fmt.Sprintf("Gate policy version created %s", string(r.Payload))
	case "proof.fetch.captured":
		e.Category, e.Summary = "ran", fmt.Sprintf("Proof captured %s (capture %s, fetched %s, compliant %s, sha256 %s)", s("url"), s("capture_id"), s("fetched"), s("compliant"), s("content_sha256"))
	case "proof.manifest.signed":
		e.Category, e.Summary = "verified", fmt.Sprintf("Proof manifest %s signed over %s captures (root %s, key %s)", s("manifest_hash"), s("capture_count"), s("captures_root"), s("key_id"))
	case "bench.task.mined":
		e.Summary = fmt.Sprintf("Bench task %s mined from %s@%s", s("task_id"), s("repo"), s("commit"))
	case "bench.run.scored":
		e.Category, e.Summary = "verified", fmt.Sprintf("Bench run %s task %s passed=%s %s", s("run_id"), s("task_id"), s("passed"), s("failure_mode"))
	case "ledger.goal.created":
		e.Category, e.Summary = "state", "Goal created: "+s("title")
	case "ledger.goal.status":
		e.Category, e.Summary = "state", "Goal status → "+s("status")
	case "ledger.step.planned":
		e.Category, e.Summary = "state", fmt.Sprintf("Step %s planned: %s", s("step_no"), s("description"))
	case "ledger.action.attempted":
		e.Category, e.Summary = "ran", fmt.Sprintf("Attempt %s: %s action %s", s("attempt_id"), s("tool"), actionRef(p))
	case "ledger.action.completed":
		e.Category, e.Summary = "effect", fmt.Sprintf("Attempt %s completed: %s", s("attempt_id"), strings.ToUpper(s("outcome")))
	case "ledger.verification.recorded":
		e.Category, e.Summary = "verified", fmt.Sprintf("Verification by %s: passed=%s", s("verifier"), s("passed"))
	case "ledger.budget.charged", "ledger.budget.allocated":
		e.Category, e.Summary = "state", fmt.Sprintf("%s %s %s", r.Type[len("ledger.budget."):], s("amount"), s("resource"))
	default:
		e.Summary = r.Type + " " + truncate(string(r.Payload), 200)
	}
	return e
}

func actionRef(p map[string]any) string {
	if a, ok := p["action"]; ok {
		return str(a)
	}
	return str(p["action_hash"])
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
