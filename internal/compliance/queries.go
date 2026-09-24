package compliance

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/keys"
	"github.com/Celaris-dev1/Ledger/internal/retention"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

// Shared evidence queries used by several templates. Each returns a Finding; the templates
// supply the regime-specific wording.

// Where returns the in-scope records matching pred.
func (ev *Evidence) Where(pred func(store.Record) bool) []store.Record {
	var out []store.Record
	for _, r := range ev.Records {
		if pred(r) {
			out = append(out, r)
		}
	}
	return out
}

// TypeIs matches exact record types.
func TypeIs(types ...string) func(store.Record) bool {
	return func(r store.Record) bool {
		for _, t := range types {
			if r.Type == t {
				return true
			}
		}
		return false
	}
}

// TypeHas matches record types containing any of the substrings.
func TypeHas(subs ...string) func(store.Record) bool {
	return func(r store.Record) bool {
		lt := strings.ToLower(r.Type)
		for _, s := range subs {
			if strings.Contains(lt, s) {
				return true
			}
		}
		return false
	}
}

func payload(r store.Record) map[string]any {
	m := map[string]any{}
	_ = json.Unmarshal(r.Payload, &m)
	return m
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func actors(r store.Record) []store.Actor {
	var a []store.Actor
	_ = json.Unmarshal(r.ActorChain, &a)
	return a
}

func hasAgent(r store.Record) bool {
	for _, a := range actors(r) {
		if a.Kind == "agent" {
			return true
		}
	}
	return false
}

// oversight record types: human approvals/denials/halts across the six products.
var oversightTypes = TypeHas("approval.granted", "approval.denied", "approval.decided", "approval.approved",
	"token.revoked", "call.denied", "run.decided", "override", "halt", "goal.transition", "admin.")

// ---- integrity / anchoring ----

func integrityFinding(ev *Evidence) Finding {
	var broken []string
	n := 0
	for _, c := range ev.Chains {
		n += c.Verify.Length
		if !c.Verify.OK {
			at := int64(0)
			if c.Verify.BrokenAt != nil {
				at = *c.Verify.BrokenAt
			}
			broken = append(broken, fmt.Sprintf("%s (broken at seq %d: %s)", c.Chain, at, c.Verify.Reason))
		}
	}
	m := map[string]any{"chains": len(ev.Chains), "records_verified": n}
	if len(ev.Chains) == 0 {
		return Finding{Status: Gap, Summary: "No chains in scope.", Metrics: m}
	}
	if len(broken) > 0 {
		return Finding{Status: Gap, Summary: "Hash-chain verification FAILED: " + strings.Join(broken, "; "), Metrics: m}
	}
	return Finding{Status: Pass, Summary: fmt.Sprintf("All %d chain(s) re-verified end to end (%d records): seq continuity, prev_hash linkage and every record hash; append-only triggers reject UPDATE/DELETE/TRUNCATE.", len(ev.Chains), n), Metrics: m}
}

func anchorFinding(ev *Evidence) Finding {
	checked, receipts, okReceipts := 0, 0, 0
	var bad, unanchored []string
	for _, c := range ev.Chains {
		if c.Anchors == nil {
			continue
		}
		checked++
		for _, a := range c.Anchors.Checks {
			receipts++
			if a.Status == "ok" {
				okReceipts++
			}
		}
		if len(c.Anchors.Checks) == 0 {
			unanchored = append(unanchored, c.Chain)
		}
		if !c.Anchors.OK {
			bad = append(bad, c.Chain+": "+strings.Join(c.Anchors.Findings, " "))
		}
	}
	m := map[string]any{"chains_checked": checked, "receipts": receipts, "receipts_ok": okReceipts}
	switch {
	case checked == 0:
		return Finding{Status: Gap, Summary: "External anchor receipts were not checked (anchoring not configured for this export); tamper-evidence rests on the database alone.", Metrics: m}
	case len(bad) > 0:
		return Finding{Status: Gap, Summary: "Anchor verification FAILED: " + strings.Join(bad, "; "), Metrics: m}
	case len(unanchored) > 0:
		return Finding{Status: Gap, Summary: "No external anchors for chain(s): " + strings.Join(unanchored, ", "), Metrics: m}
	}
	return Finding{Status: Pass, Summary: fmt.Sprintf("%d external anchor receipt(s) re-verified offline across %d chain(s); every anchored head is still on its chain (no rewritten history).", okReceipts, checked), Metrics: m}
}

func keyRotationFinding(ev *Evidence) Finding {
	m := map[string]any{"rotations": len(ev.Rotations)}
	if len(ev.RotErrors) > 0 {
		return Finding{Status: Gap, Summary: "Key rotation records failed verification: " + strings.Join(ev.RotErrors, "; "), Metrics: m}
	}
	if len(ev.Rotations) == 0 {
		return Finding{Status: Manual, Summary: "No root-key rotations recorded; key custody and rotation schedule must be evidenced outside Ledger.", Metrics: m}
	}
	return Finding{Status: Pass, Summary: fmt.Sprintf("%d root-key rotation(s) recorded in the ledger system chain, each cross-signed by the retiring and the new key.", len(ev.Rotations)), Metrics: m}
}

// ---- logging / actors ----

func loggingFinding(ev *Evidence) Finding {
	types := map[string]int{}
	for _, r := range ev.Records {
		types[r.Type]++
	}
	m := map[string]any{"records": len(ev.Records), "record_types": types}
	if len(ev.Records) == 0 {
		return Finding{Status: Gap, Summary: "No records in scope: no automatically recorded events for this period.", Metrics: m}
	}
	integ := integrityFinding(ev)
	if integ.Status != Pass {
		return Finding{Status: Gap, Summary: fmt.Sprintf("%d events recorded, but integrity verification failed.", len(ev.Records)), Metrics: m}
	}
	return Finding{Status: Pass, Summary: fmt.Sprintf("%d events of %d types recorded automatically by the emitting systems into hash-chained, append-only chains.", len(ev.Records), len(types)), Count: len(ev.Records), Metrics: m}
}

func humanOriginFinding(ev *Evidence) Finding {
	humans := map[string]bool{}
	var missing []store.Record
	for _, r := range ev.Records {
		a := actors(r)
		if len(a) == 0 || a[0].Kind != "human" || a[0].ID == "" {
			missing = append(missing, r)
			continue
		}
		humans[a[0].ID] = true
	}
	m := map[string]any{"originating_humans": sortedKeys(humans)}
	if len(ev.Records) == 0 {
		return Finding{Status: Gap, Summary: "No records in scope.", Metrics: m}
	}
	if len(missing) > 0 {
		return Finding{Status: Gap, Summary: fmt.Sprintf("%d record(s) lack an originating human.", len(missing)), Count: len(missing), Evidence: refs(missing), Metrics: m}
	}
	return Finding{Status: Pass, Summary: fmt.Sprintf("All %d records attribute the action to an originating natural person (%d distinct) followed by the delegating agents/services.", len(ev.Records), len(humans)), Count: len(ev.Records), Metrics: m}
}

func agentIdentityFinding(ev *Evidence) Finding {
	withModel, without := map[string]bool{}, map[string]bool{}
	for _, r := range ev.Records {
		for _, a := range actors(r) {
			if a.Kind == "agent" {
				if a.Model != "" {
					withModel[a.ID+" ("+a.Model+"@"+a.ModelVersion+")"] = true
				} else {
					without[a.ID] = true
				}
			}
		}
	}
	m := map[string]any{"agents_with_model": sortedKeys(withModel), "agents_without_model": sortedKeys(without)}
	switch {
	case len(withModel) == 0 && len(without) == 0:
		return Finding{Status: Manual, Summary: "No agent actors in scope.", Metrics: m}
	case len(without) > 0:
		return Finding{Status: Gap, Summary: fmt.Sprintf("%d agent(s) acted without a recorded model/version identifier: %s.", len(without), strings.Join(sortedKeys(without), ", ")), Metrics: m}
	}
	return Finding{Status: Pass, Summary: fmt.Sprintf("Every acting agent is identified with its model and version (%d).", len(withModel)), Metrics: m}
}

func oversightFinding(ev *Evidence) Finding {
	recs := ev.Where(oversightTypes)
	if len(recs) == 0 {
		return Finding{Status: Gap, Summary: "No human approval, denial, revocation, halt or gate-decision records in scope.", Evidence: []Ref{}}
	}
	return Finding{Status: Pass, Summary: fmt.Sprintf("%d oversight/intervention record(s): approvals, denials, revocations, gate decisions and state transitions.", len(recs)), Count: len(recs), Evidence: refs(recs)}
}

// dualControlFinding looks for decisions where the decider differs from the requester.
func dualControlFinding(ev *Evidence) Finding {
	req := map[string]string{} // request_id -> requesting human
	for _, r := range ev.Where(TypeHas("approval.requested")) {
		if a := actors(r); len(a) > 0 {
			req[str(payload(r), "request_id")] = a[0].ID
		}
	}
	var dual []store.Record
	for _, r := range ev.Where(TypeHas("approval.granted", "approval.denied", "approval.decided")) {
		p := payload(r)
		decider := str(p, "decided_by")
		if a := actors(r); decider == "" && len(a) > 0 {
			decider = a[0].ID
		}
		if rq, ok := req[str(p, "request_id")]; ok && decider != "" && decider != rq {
			dual = append(dual, r)
		}
	}
	if len(dual) == 0 {
		return Finding{Status: Manual, Summary: "No decisions in scope were made by a person other than the requester; where two-person verification is required it must be evidenced separately."}
	}
	return Finding{Status: Pass, Summary: fmt.Sprintf("%d decision(s) were taken by a different natural person than the requester.", len(dual)), Count: len(dual), Evidence: refs(dual)}
}

// ---- retention ----

func retentionFinding(ev *Evidence, regime, minimum string) Finding {
	floor := retention.Policy{MinRetention: minimum}
	t0 := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	var ok, short, none []string
	for _, c := range ev.Chains {
		p, has := ev.Retention.PolicyFor(c.Chain)
		switch {
		case !has:
			none = append(none, c.Chain)
		case p.Until(t0).Before(floor.Until(t0)):
			short = append(short, fmt.Sprintf("%s (%s)", c.Chain, p.MinRetention))
		default:
			ok = append(ok, fmt.Sprintf("%s (%s)", c.Chain, p.MinRetention))
		}
	}
	overrides := 0
	for _, e := range ev.Retention.Erasures {
		if e.RetentionOverride != "" {
			overrides++
		}
	}
	m := map[string]any{"required_minimum": minimum, "compliant_chains": ok, "short_policies": short, "chains_without_policy": none,
		"erasures": len(ev.Retention.Erasures), "erasures_with_retention_override": overrides, "active_legal_holds": len(ev.Retention.ActiveHolds())}
	if len(ev.Chains) == 0 {
		return Finding{Status: Gap, Summary: "No chains in scope.", Metrics: m}
	}
	if len(short)+len(none) > 0 {
		parts := []string{}
		if len(none) > 0 {
			parts = append(parts, "no retention policy on "+strings.Join(none, ", "))
		}
		if len(short) > 0 {
			parts = append(parts, "policy shorter than "+minimum+" on "+strings.Join(short, ", "))
		}
		return Finding{Status: Gap, Summary: fmt.Sprintf("%s minimum retention (%s) not evidenced: %s. (Records are never deleted by Ledger, but no policy commits to keeping them.)", regime, minimum, strings.Join(parts, "; ")), Metrics: m}
	}
	s := fmt.Sprintf("Every chain in scope has a recorded retention policy of at least %s; records are append-only and expiry never deletes.", minimum)
	if overrides > 0 {
		s += fmt.Sprintf(" Note: %d erasure(s) shredded payloads inside a retention period with a recorded justification.", overrides)
	}
	return Finding{Status: Pass, Summary: s, Metrics: m}
}

// ---- incidents ----

type incident struct {
	rec      store.Record
	id       string
	category string
}

func seriousIncidents(ev *Evidence) []incident {
	var out []incident
	for _, r := range ev.Records {
		lt := strings.ToLower(r.Type)
		if !strings.Contains(lt, "incident") || strings.Contains(lt, "reported") || strings.Contains(lt, "resolved") {
			continue
		}
		p := payload(r)
		if strings.HasSuffix(lt, "incident.serious") || strings.EqualFold(str(p, "severity"), "serious") {
			id := str(p, "incident_id")
			if id == "" {
				id = r.ID
			}
			out = append(out, incident{r, id, str(p, "category")})
		}
	}
	return out
}

// Art. 73 deadlines: 15 days generally, 2 days for widespread infringement / critical
// infrastructure, 10 days in case of death.
func art73Deadline(category string) time.Duration {
	switch strings.ToLower(category) {
	case "widespread", "critical_infrastructure":
		return 2 * 24 * time.Hour
	case "death":
		return 10 * 24 * time.Hour
	}
	return 15 * 24 * time.Hour
}

func incidentReportingFinding(ev *Evidence) Finding {
	inc := seriousIncidents(ev)
	reported := map[string]store.Record{}
	for _, r := range ev.Where(TypeHas("incident.reported")) {
		if id := str(payload(r), "incident_id"); id != "" {
			if _, dup := reported[id]; !dup {
				reported[id] = r
			}
		}
	}
	if len(inc) == 0 {
		return Finding{Status: Manual, Summary: "No serious-incident records in scope. Ledger cannot evidence that no serious incident occurred; emit `ledger.incident.serious` (payload incident_id, category) and `ledger.incident.reported` records to use this hook."}
	}
	var late, missing, ok []store.Record
	for _, i := range inc {
		rep, has := reported[i.id]
		switch {
		case !has:
			missing = append(missing, i.rec)
		case rep.CreatedAt.Sub(i.rec.CreatedAt) > art73Deadline(i.category):
			late = append(late, rep)
		default:
			ok = append(ok, rep)
		}
	}
	all := append(append(append([]store.Record{}, missing...), late...), ok...)
	m := map[string]any{"serious_incidents": len(inc), "reported_on_time": len(ok), "reported_late": len(late), "unreported": len(missing)}
	if len(missing)+len(late) > 0 {
		return Finding{Status: Gap, Summary: fmt.Sprintf("%d serious incident(s): %d unreported, %d reported after the Art. 73 deadline.", len(inc), len(missing), len(late)), Count: len(all), Evidence: refs(all), Metrics: m}
	}
	return Finding{Status: Pass, Summary: fmt.Sprintf("All %d serious incident(s) have a report record within the applicable Art. 73 deadline.", len(inc)), Count: len(all), Evidence: refs(all), Metrics: m}
}

func incidentResponseFinding(ev *Evidence) Finding {
	open := map[string]store.Record{}
	var all []store.Record
	for _, r := range ev.Where(TypeHas("incident")) {
		all = append(all, r)
		id := str(payload(r), "incident_id")
		if id == "" {
			continue
		}
		if strings.Contains(strings.ToLower(r.Type), "resolved") {
			delete(open, id)
		} else if _, seen := open[id]; !seen && !strings.Contains(strings.ToLower(r.Type), "reported") {
			open[id] = r
		}
	}
	if len(all) == 0 {
		return Finding{Status: Manual, Summary: "No incident records in scope; the incident-response procedure must be evidenced outside Ledger."}
	}
	if len(open) > 0 {
		var o []store.Record
		for _, r := range open {
			o = append(o, r)
		}
		return Finding{Status: Gap, Summary: fmt.Sprintf("%d incident(s) without a resolution record.", len(open)), Count: len(o), Evidence: refs(o)}
	}
	return Finding{Status: Pass, Summary: fmt.Sprintf("%d incident record(s); every identified incident has a resolution record.", len(all)), Count: len(all), Evidence: refs(all)}
}

// ---- access control (Warrant) ----

func tokenIssuanceFinding(ev *Evidence) Finding {
	issued := ev.Where(TypeIs("warrant.token.issued"))
	if len(issued) == 0 {
		return Finding{Status: Gap, Summary: "No Warrant capability tokens issued in scope: agent access is not evidenced as scoped and authorised."}
	}
	var unscoped []store.Record
	for _, r := range issued {
		if sc, _ := payload(r)["scopes"].([]any); len(sc) == 0 {
			unscoped = append(unscoped, r)
		}
	}
	if len(unscoped) > 0 {
		return Finding{Status: Gap, Summary: fmt.Sprintf("%d token(s) issued without scopes.", len(unscoped)), Count: len(unscoped), Evidence: refs(unscoped)}
	}
	return Finding{Status: Pass, Summary: fmt.Sprintf("%d scoped capability token(s) issued, each attributed to an originating human.", len(issued)), Count: len(issued), Evidence: refs(issued)}
}

func enforcementFinding(ev *Evidence) Finding {
	allowed := ev.Where(TypeIs("warrant.call.allowed"))
	denied := ev.Where(TypeIs("warrant.call.denied"))
	m := map[string]any{"calls_allowed": len(allowed), "calls_denied": len(denied)}
	if len(allowed)+len(denied) == 0 {
		return Finding{Status: Gap, Summary: "No access decisions (warrant.call.*) recorded: enforcement is not evidenced.", Metrics: m}
	}
	all := append(append([]store.Record{}, denied...), allowed...)
	return Finding{Status: Pass, Summary: fmt.Sprintf("%d access decision(s) recorded (%d denied).", len(all), len(denied)), Count: len(all), Evidence: refs(all), Metrics: m}
}

func revocationFinding(ev *Evidence) Finding {
	rev := ev.Where(TypeIs("warrant.token.revoked"))
	var expiring int
	for _, r := range ev.Where(TypeIs("warrant.token.issued")) {
		p := payload(r)
		if p["expires_at"] != nil || p["ttl"] != nil || p["max_calls"] != nil {
			expiring++
		}
	}
	m := map[string]any{"revocations": len(rev), "bounded_tokens": expiring}
	if len(rev) == 0 && expiring == 0 {
		return Finding{Status: Manual, Summary: "No revocations or bounded (expiring / call-limited) tokens in scope; access removal must be evidenced separately.", Metrics: m}
	}
	return Finding{Status: Pass, Summary: fmt.Sprintf("%d revocation(s); %d token(s) bounded by expiry or call limits.", len(rev), expiring), Count: len(rev), Evidence: refs(rev), Metrics: m}
}

// ---- change management (Gate) ----

func changeMgmtFinding(ev *Evidence) Finding {
	started := map[string]store.Record{}
	decided := map[string]store.Record{}
	for _, r := range ev.Where(TypeIs("gate.run.started")) {
		started[str(payload(r), "run_id")] = r
	}
	for _, r := range ev.Where(TypeIs("gate.run.decided", "gate.run.enforced")) {
		decided[str(payload(r), "run_id")] = r
	}
	approvals := ev.Where(TypeHas("approval.granted", "approval.denied", "approval.decided"))
	m := map[string]any{"gate_runs": len(started), "gate_decisions": len(decided), "approvals": len(approvals)}
	if len(started) == 0 {
		return Finding{Status: Gap, Summary: "No Gate runs in scope: changes are not evidenced as tested and authorised before deployment.", Metrics: m}
	}
	var undecided []store.Record
	for id, r := range started {
		if _, ok := decided[id]; !ok {
			undecided = append(undecided, r)
		}
	}
	if len(undecided) > 0 {
		return Finding{Status: Gap, Summary: fmt.Sprintf("%d Gate run(s) have no recorded decision.", len(undecided)), Count: len(undecided), Evidence: refs(undecided), Metrics: m}
	}
	var ev2 []store.Record
	for _, r := range decided {
		ev2 = append(ev2, r)
	}
	sort.Slice(ev2, func(i, j int) bool { return ev2[i].CreatedAt.Before(ev2[j].CreatedAt) })
	ev2 = append(ev2, approvals...)
	return Finding{Status: Pass, Summary: fmt.Sprintf("Every one of %d Gate run(s) reached a recorded decision; %d human approval decision(s).", len(started), len(approvals)), Count: len(ev2), Evidence: refs(ev2), Metrics: m}
}

func policyVersionFinding(ev *Evidence) Finding {
	pv := map[string]bool{}
	for _, r := range ev.Records {
		if r.PolicyVersion != "" {
			pv[r.PolicyVersion] = true
		}
	}
	created := ev.Where(TypeHas("policy.version.created"))
	m := map[string]any{"policy_versions": sortedKeys(pv), "policy_changes": len(created)}
	if len(pv) == 0 && len(created) == 0 {
		return Finding{Status: Gap, Summary: "No policy versions recorded on decisions: configuration changes cannot be traced.", Metrics: m}
	}
	return Finding{Status: Pass, Summary: fmt.Sprintf("Decisions reference %d policy version(s); %d policy change record(s).", len(pv), len(created)), Count: len(created), Evidence: refs(created), Metrics: m}
}

func riskSignalsFinding(ev *Evidence) Finding {
	risk := ev.Where(func(r store.Record) bool {
		p := payload(r)
		return p["risk"] != nil || strings.EqualFold(str(p, "status"), "fail") || r.Type == "warrant.call.denied" ||
			strings.EqualFold(str(p, "decision"), "block") || strings.Contains(r.Type, "incident")
	})
	if len(risk) == 0 {
		return Finding{Status: Manual, Summary: "No risk-scored or blocked events in scope."}
	}
	return Finding{Status: Pass, Summary: fmt.Sprintf("%d risk-relevant event(s) recorded (risk scores, failed checks, blocks, denials, incidents).", len(risk)), Count: len(risk), Evidence: refs(risk)}
}

func replayabilityFinding(ev *Evidence) Finding {
	goals := map[string]bool{}
	for _, r := range ev.Records {
		if r.GoalID != "" {
			goals[r.GoalID] = true
		}
	}
	if len(ev.Records) == 0 {
		return Finding{Status: Gap, Summary: "No records in scope."}
	}
	if len(goals) == 0 {
		return Finding{Status: Gap, Summary: "Records carry no goal_id: decisions cannot be replayed per task."}
	}
	return Finding{Status: Pass, Summary: fmt.Sprintf("Records are linked to %d goal(s) and replayable in order per goal (GET /v1/goals/{id}/replay).", len(goals)), Metrics: map[string]any{"goals": len(goals)}}
}

func backupFinding(ev *Evidence) Finding {
	b := ev.Where(TypeIs("ledger.backup.created"))
	if len(b) == 0 {
		return Finding{Status: Gap, Summary: "No signed Ledger backups recorded in scope (`ledger backup` records ledger.backup.created)."}
	}
	return Finding{Status: Pass, Summary: fmt.Sprintf("%d signed, hash-listed logical backup(s) recorded.", len(b)), Count: len(b), Evidence: refs(b)}
}

func encryptionFinding(ev *Evidence) Finding {
	n := 0
	for _, r := range ev.Records {
		if _, ok := keys.ParseEnvelope(r.Payload); ok {
			n++
		}
	}
	m := map[string]any{"encrypted_payloads": n, "records": len(ev.Records)}
	if n == 0 {
		return Finding{Status: Manual, Summary: "No payloads in scope use Ledger's per-subject envelope encryption; encryption at rest must be evidenced at the storage layer.", Metrics: m}
	}
	return Finding{Status: Pass, Summary: fmt.Sprintf("%d of %d payloads are AES-256-GCM encrypted with per-subject data keys (crypto-shreddable).", n, len(ev.Records)), Metrics: m}
}

func manual(summary string) func(*Evidence) Finding {
	return func(*Evidence) Finding { return Finding{Status: Manual, Summary: summary} }
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
