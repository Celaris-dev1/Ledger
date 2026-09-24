//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const secretName = "Jane Roe-4711"

// seedClinic appends a realistic multi-product dataset: a Warrant token and calls, a Gate run, a
// Harbour goal with a two-phase effect, human approvals, a serious incident that is reported in
// time, and a clinic chain whose notes are encrypted per data subject.
func seedClinic(t *testing.T, d *Daemon, token string) {
	t.Helper()
	ac := []Actor{human("dr-house"), agent("triage-bot")}
	g := "g-clinic"
	action := map[string]any{"tool": "ehr.update", "args": map[string]any{"patient": "p1", "field": "dose"}}
	for _, r := range []map[string]any{
		{"chain": "warrant", "type": "warrant.token.issued", "payload": map[string]any{"token_id": "tok-1", "subject": "spiffe://w/triage", "max_calls": 5, "scopes": []any{map[string]any{"tool": "ehr.*"}}}},
		{"chain": "warrant", "type": "warrant.call.allowed", "payload": map[string]any{"token_id": "tok-1", "tool": "ehr.update", "resource": "p1", "action_hash": "abc"}},
		{"chain": "warrant", "type": "warrant.call.denied", "payload": map[string]any{"token_id": "tok-1", "tool": "ehr.delete", "resource": "p1", "reason": "forbid", "action_hash": "def"}},
		{"chain": "warrant", "type": "warrant.token.revoked", "payload": map[string]any{"token_id": "tok-1", "reason": "shift over"}},
		{"chain": "gate", "type": "gate.run.started", "payload": map[string]any{"run_id": "run-1", "repo": "clinic/ehr", "base": "a", "head": "b"}},
		{"chain": "gate", "type": "gate.stage.completed", "payload": map[string]any{"run_id": "run-1", "stage": "tests", "passed": true}},
		{"chain": "gate", "type": "gate.run.decided", "payload": map[string]any{"run_id": "run-1", "decision": "allow"}},
		{"chain": "harbour", "type": "harbour.goal.transition", "payload": map[string]any{"goal_name": "dose change", "from": "planned", "to": "running"}},
		{"chain": "harbour", "type": "harbour.effect.intent", "payload": map[string]any{"effect_id": "e1", "tool": "ehr.update", "args": map[string]any{"p": "p1"}, "idem_key": "k1", "step": 1}},
		{"chain": "ops", "type": "ledger.approval.requested", "payload": map[string]any{"request_id": "rq-1", "action": action}},
		{"chain": "ops", "type": "ledger.approval.granted", "payload": map[string]any{"request_id": "rq-1", "action": action}},
		{"chain": "harbour", "type": "harbour.effect.result", "payload": map[string]any{"effect_id": "e1", "status": "committed"}},
		{"chain": "ops", "type": "ledger.incident.serious", "payload": map[string]any{"incident_id": "inc-1", "category": "health"}},
		{"chain": "ops", "type": "ops.incident.reported", "payload": map[string]any{"incident_id": "inc-1", "authority": "BfArM"}},
		{"chain": "ops", "type": "ops.incident.resolved", "payload": map[string]any{"incident_id": "inc-1"}},
		{"chain": "harbour", "type": "harbour.goal.transition", "payload": map[string]any{"goal_name": "dose change", "from": "running", "to": "done"}},
	} {
		r["goal_id"], r["actor_chain"], r["policy_version"] = g, ac, "clinic-pol-3"
		d.Append(token, r)
	}
	for i, subj := range []string{"patient-1", "patient-1", "patient-2"} {
		d.Append(token, map[string]any{"chain": "clinic", "type": "clinic.note", "goal_id": g, "actor_chain": ac, "data_subject": subj,
			"payload": map[string]any{"name": map[bool]string{true: secretName, false: "John Doe"}[subj == "patient-1"], "note": "dose adjusted", "i": i}})
	}
}

func controls(t *testing.T, path string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Controls []map[string]any `json:"controls"`
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, c := range rep.Controls {
		out[str(c["id"])] = str(c["status"])
	}
	if len(out) == 0 {
		t.Fatalf("no controls in %s:\n%.2000s", path, b)
	}
	return out
}

func TestComplianceRetentionErasureBackupRestore(t *testing.T) {
	e := NewEnv(t)
	e = e.With("LEDGER_KEYRING_DIR", filepath.Join(e.Dir, "keyring"), "LEDGER_DATA_KEY_DIR", filepath.Join(e.Dir, "datakeys"))
	d := e.Start()
	seedClinic(t, d, "")
	d.Stop()
	e.MustLedger("retention", "set", "--chain", "*", "--regime", "hipaa", "--operator", "cco")
	e.MustLedger("anchor", "--external")

	// Regime packs for all three regimes; JSON and PDF must verify, a tampered copy must not.
	for _, regime := range []string{"eu-ai-act", "soc2", "hipaa"} {
		out := filepath.Join(e.Dir, "pack-"+regime)
		e.MustLedger("export", "--regime", regime, "--out", out)
		for _, f := range []string{"report.json", "report.pdf", "report.html"} {
			if _, err := os.Stat(filepath.Join(out, f)); err != nil {
				t.Fatalf("%s: %v", regime, err)
			}
		}
		for _, f := range []string{"report.json", "report.pdf"} {
			if so := e.MustLedger("export", "--verify", filepath.Join(out, f)); !strings.HasPrefix(so, "OK") {
				t.Fatalf("%s %s: %s", regime, f, so)
			}
		}
		cs := controls(t, filepath.Join(out, "report.json"))
		pass := 0
		for _, r := range cs {
			if r == "pass" {
				pass++
			}
		}
		if pass == 0 {
			t.Errorf("%s: no control passes on a realistic dataset: %v", regime, cs)
		}
		t.Logf("%s controls: %v", regime, cs)
		// The integrity controls: every chain verifies and every anchor receipt re-verifies.
		for id, r := range cs {
			if (strings.HasSuffix(id, "INT-1") || strings.HasSuffix(id, "INT-2")) && r != "pass" {
				t.Errorf("%s %s = %s on an intact, freshly anchored ledger", regime, id, r)
			}
		}
		b, _ := os.ReadFile(filepath.Join(out, "report.json"))
		bad := filepath.Join(out, "tampered.json")
		_ = os.WriteFile(bad, bytes.Replace(b, []byte(`"pass"`), []byte(`"gap"`), 1), 0o644)
		if so, _, code := e.Ledger("export", "--verify", bad); code == 0 {
			t.Fatalf("%s: tampered report verified: %s", regime, so)
		}
		// Editing what the auditor sees in the PDF (here: the document title in the metadata,
		// leaving the embedded report.json intact) must not verify either.
		pdf, _ := os.ReadFile(filepath.Join(out, "report.pdf"))
		i := bytes.Index(pdf, []byte("/Title"))
		if i < 0 {
			t.Fatalf("%s: no /Title in PDF", regime)
		}
		pdf[i+8] ^= 1
		badPDF := filepath.Join(out, "tampered.pdf")
		_ = os.WriteFile(badPDF, pdf, 0o644)
		if so, _, code := e.Ledger("export", "--verify", badPDF); code == 0 {
			t.Fatalf("%s: PDF with edited metadata verified: %s", regime, so)
		}
	}
	hip := controls(t, filepath.Join(e.Dir, "pack-hipaa", "report.json"))
	for id, r := range hip {
		if id == "164.316(b)(2)(i)" && r != "pass" {
			t.Errorf("HIPAA %s = %s after a 6y retention policy on every chain", id, r)
		}
	}

	// Legal hold blocks erasure; retention minimum blocks it until overridden.
	e.MustLedger("hold", "create", "--id", "lit-7", "--reason", "Doe v. Clinic", "--chain", "clinic", "--operator", "counsel")
	if so, se, code := e.Ledger("erase", "--subject", "patient-1", "--reason", "DSR #88", "--basis", "GDPR Art. 17", "--operator", "dpo", "--override-retention", "dup of EHR"); code == 0 {
		t.Fatalf("erase went through an active legal hold:\n%s%s", so, se)
	}
	e.MustLedger("hold", "release", "--id", "lit-7", "--reason", "settled", "--operator", "counsel")
	if so, se, code := e.Ledger("erase", "--subject", "patient-1", "--reason", "DSR #88", "--basis", "GDPR Art. 17", "--operator", "dpo"); code == 0 {
		t.Fatalf("erase inside HIPAA minimum retention without override:\n%s%s", so, se)
	}
	e.MustLedger("erase", "--subject", "patient-1", "--reason", "DSR #88", "--basis", "GDPR Art. 17", "--operator", "dpo", "--override-retention", "duplicate of EHR record")

	d.Restart()
	for _, c := range []string{"clinic", "ledger", "warrant", "gate", "harbour", "ops"} {
		d.VerifyOK("", c)
	}
	e.MustLedger("verify")
	// Plaintext is gone: not in the database, not in the data-key directory, not via the API.
	dump := e.PSQL(`SELECT string_agg(payload::text, E'\n') FROM records`)
	if strings.Contains(dump, secretName) || strings.Contains(dump, "John Doe") {
		t.Fatalf("plaintext subject data stored in the database")
	}
	if !strings.Contains(dump, "ledger-envelope/v1") {
		t.Fatalf("clinic payloads are not envelopes:\n%.1000s", dump)
	}
	_ = filepath.Walk(e.Vars["LEDGER_DATA_KEY_DIR"], func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			b, _ := os.ReadFile(p)
			if bytes.Contains(b, []byte(secretName)) {
				t.Errorf("plaintext in %s", p)
			}
		}
		return nil
	})
	if r := d.Do("GET", "/v1/records?chain=clinic", "", nil); strings.Contains(string(r.Body), secretName) {
		t.Fatal("API returns erased plaintext")
	}
	r := d.Do("POST", "/v1/records", "", map[string]any{"chain": "clinic", "type": "clinic.note", "data_subject": "patient-1",
		"actor_chain": []Actor{human("dr-house")}, "payload": map[string]any{"name": secretName}})
	if r.Status != 409 {
		t.Fatalf("writing to an erased subject: %d %s (want 409)", r.Status, r.Body)
	}
	if r := d.Do("POST", "/v1/records", "", map[string]any{"chain": "clinic", "type": "clinic.note", "data_subject": "patient-2",
		"actor_chain": []Actor{human("dr-house")}, "payload": map[string]any{"name": "John Doe"}}); r.Status != 201 {
		t.Fatalf("other subjects must still be writable: %d %s", r.Status, r.Body)
	}
	d.Stop()

	// Backup, restore into a brand-new database, and everything verifies there.
	bk := filepath.Join(e.Dir, "backup")
	e.MustLedger("backup", "--out", bk, "--operator", "ops")
	fresh := NewDatabaseEnv(t).With("LEDGER_KEYRING_DIR", e.Vars["LEDGER_KEYRING_DIR"], "LEDGER_ANCHOR_DIR", e.Vars["LEDGER_ANCHOR_DIR"])
	fresh.MustLedger("restore", "--in", bk, "--verify-only")
	fresh.MustLedger("restore", "--in", bk)
	vo := fresh.MustLedger("verify")
	for _, c := range []string{"clinic", "ledger", "warrant", "gate", "harbour", "ops"} {
		if !strings.Contains(vo, "OK      "+c) {
			t.Fatalf("restored %s missing/broken:\n%s", c, vo)
		}
	}
	if so, _, code := fresh.Ledger("verify", "--anchors"); code != 0 {
		t.Fatalf("restored anchors do not verify:\n%s", so)
	}
	// Same heads as the source, except the source's "ledger" chain, which gained the
	// ledger.backup.created record after the snapshot.
	dropLedger := func(s string) string {
		var keep []string
		for _, l := range strings.Split(s, "\n") {
			if !strings.Contains(l, " ledger ") {
				keep = append(keep, l)
			}
		}
		return strings.Join(keep, "\n")
	}
	orig := e.MustLedger("verify")
	if dropLedger(orig) != dropLedger(vo) {
		t.Fatalf("restored heads differ:\n%s\nvs\n%s", orig, vo)
	}
	fresh.MustLedger("project", "--rebuild")
	if so := fresh.MustLedger("export", "--regime", "soc2", "--out", filepath.Join(fresh.Dir, "p")); !strings.Contains(so, "pass") {
		t.Fatalf("export after restore: %s", so)
	}

	// A tampered backup is refused (verify-only and restore), and nothing is written.
	bad := filepath.Join(e.Dir, "backup-tampered")
	if err := copyDir(bk, bad); err != nil {
		t.Fatal(err)
	}
	gp := filepath.Join(bad, "chains")
	ents, _ := os.ReadDir(gp)
	var target string
	for _, en := range ents {
		if strings.Contains(en.Name(), "gate") {
			target = filepath.Join(gp, en.Name())
		}
	}
	if target == "" {
		t.Fatalf("no gate chain file in backup: %v", ents)
	}
	b, _ := os.ReadFile(target)
	_ = os.WriteFile(target, bytes.Replace(b, []byte(`allow`), []byte(`block`), 1), 0o644)
	other := NewDatabaseEnv(t).With("LEDGER_KEYRING_DIR", e.Vars["LEDGER_KEYRING_DIR"])
	if so, se, code := other.Ledger("restore", "--in", bad, "--verify-only"); code == 0 {
		t.Fatalf("tampered backup verified:\n%s%s", so, se)
	}
	if so, se, code := other.Ledger("restore", "--in", bad); code == 0 {
		t.Fatalf("tampered backup restored:\n%s%s", so, se)
	}
	if so, _, _ := other.Ledger("verify"); strings.Contains(so, "gate") {
		t.Fatalf("refused restore still wrote data:\n%s", so)
	}
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		t := filepath.Join(dst, rel)
		if fi.IsDir() {
			return os.MkdirAll(t, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(t, b, fi.Mode())
	})
}
