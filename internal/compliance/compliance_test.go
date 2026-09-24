package compliance

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/keys"
	"github.com/Celaris-dev1/Ledger/internal/retention"
	"github.com/Celaris-dev1/Ledger/internal/store"
	"github.com/Celaris-dev1/Ledger/internal/testfix"
)

var now = time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)

func control(r Report, id string) ControlResult {
	for _, c := range r.Controls {
		if c.ID == id {
			return c
		}
	}
	panic("no control " + id)
}

func TestRegistry(t *testing.T) {
	if got := strings.Join(Regimes(), ","); got != "eu-ai-act,hipaa,soc2" {
		t.Fatal(got)
	}
	tp, err := Lookup("hipaa", "")
	if err != nil || tp.ID() != "hipaa@2026.09" {
		t.Fatal(tp.ID(), err)
	}
	if _, err := Lookup("hipaa", "1999.01"); err == nil {
		t.Fatal("unknown version accepted")
	}
	if _, err := Lookup("pci", ""); err == nil {
		t.Fatal("unknown regime accepted")
	}
	seen := map[string]bool{}
	for _, rg := range Regimes() {
		tp, _ := Lookup(rg, "")
		for _, s := range tp.Sections {
			for _, c := range s.Controls {
				if c.ID == "" || c.Citation == "" || c.Requirement == "" || c.EvidenceQuery == "" || c.Eval == nil {
					t.Fatalf("%s: incomplete control %+v", rg, c)
				}
				if seen[c.ID] {
					t.Fatalf("duplicate control id %s", c.ID)
				}
				seen[c.ID] = true
			}
		}
	}
}

// With no evidence, no template may claim a pass.
func TestNoEvidenceNoPass(t *testing.T) {
	for _, rg := range Regimes() {
		tp, _ := Lookup(rg, "")
		r := Evaluate(tp, EvidenceFromRecords(nil, Scope{}, now))
		if r.Totals.Pass != 0 {
			for _, c := range r.Controls {
				if c.Status == Pass {
					t.Errorf("%s %s passes without evidence: %s", rg, c.ID, c.Summary)
				}
			}
		}
		if r.Totals.Gap == 0 {
			t.Errorf("%s: an empty ledger shows no gaps", rg)
		}
	}
}

func withPolicies(b *testfix.Builder, regime string, chains ...string) {
	for _, c := range chains {
		b.Add("ledger", retention.TypePolicySet, "", testfix.Actors("compliance-officer", "svc:ledger-retention"),
			map[string]any{"chain": c, "regime": regime, "min_retention": retention.RegimeMinimums[regime]})
	}
}

func TestMultiProductFixture(t *testing.T) {
	b := testfix.MultiProduct()
	ev := EvidenceFromRecords(b.Recs, Scope{}, now)
	soc, _ := Lookup("soc2", "")
	r := Evaluate(soc, ev)
	for id, want := range map[string]string{"CC6.1": Pass, "CC6.8": Pass, "CC8.1": Pass, "CC7.5": Gap, "SOC2-INT-1": Pass, "SOC2-INT-2": Gap, "CC7.4": Manual} {
		if c := control(r, id); c.Status != want {
			t.Errorf("%s = %s (%s), want %s", id, c.Status, c.Summary, want)
		}
	}
	if c := control(r, "CC8.1"); c.Count == 0 || len(c.Evidence) == 0 || c.Evidence[0].Hash == "" {
		t.Fatal("pass without evidence refs")
	}
	// the fixture's agents carry no model identifier -> gap, never silently passed
	aia, _ := Lookup("eu-ai-act", "")
	ra := Evaluate(aia, ev)
	if c := control(ra, "AIA-12.2c"); c.Status != Gap {
		t.Fatal(c.Status, c.Summary)
	}
	if c := control(ra, "AIA-19.1"); c.Status != Gap {
		t.Fatal("retention passes without a policy")
	}
	// HIPAA retention: gap until every chain has a >=6y policy
	hp, _ := Lookup("hipaa", "")
	if c := control(Evaluate(hp, ev), "164.316(b)(2)(i)"); c.Status != Gap {
		t.Fatal(c.Summary)
	}
	withPolicies(b, "hipaa", "harbour", "warrant", "ledger", "proof", "gate", "bench")
	rh := Evaluate(hp, EvidenceFromRecords(b.Recs, Scope{}, now))
	if c := control(rh, "164.316(b)(2)(i)"); c.Status != Pass {
		t.Fatal(c.Summary)
	}
	// an EU AI Act 6-month policy does not satisfy HIPAA's 6 years
	b2 := testfix.MultiProduct()
	withPolicies(b2, "eu-ai-act", "harbour", "warrant", "ledger", "proof", "gate", "bench")
	if c := control(Evaluate(hp, EvidenceFromRecords(b2.Recs, Scope{}, now)), "164.316(b)(2)(i)"); c.Status != Gap {
		t.Fatal("6m policy accepted for HIPAA")
	}
	if c := control(Evaluate(aia, EvidenceFromRecords(b2.Recs, Scope{}, now)), "AIA-26.6"); c.Status != Pass {
		t.Fatal(c.Summary)
	}
	// time window and goal scope
	ev2 := EvidenceFromRecords(b.Recs, Scope{GoalID: "goal-incident-7", From: b.T0.Add(5 * time.Second)}, now)
	for _, rec := range ev2.Records {
		if rec.GoalID != "goal-incident-7" || rec.CreatedAt.Before(b.T0.Add(5*time.Second)) {
			t.Fatal("scope not applied")
		}
	}
}

func TestIntegrityFailureIsAGap(t *testing.T) {
	b := testfix.MultiProduct()
	recs := append([]store.Record(nil), b.Recs...)
	recs[3].Payload = json.RawMessage(`{"request_id":"apr-1","action":{"tool":"rm -rf"}}`)
	for _, rg := range Regimes() {
		tp, _ := Lookup(rg, "")
		r := Evaluate(tp, EvidenceFromRecords(recs, Scope{}, now))
		if r.Integrity.AllChainsIntact {
			t.Fatal("tampering not detected")
		}
		for _, c := range r.Controls {
			if strings.HasSuffix(c.ID, "-INT-1") && c.Status != Gap {
				t.Fatalf("%s: %s", rg, c.Status)
			}
		}
	}
}

type mk struct {
	recs  []store.Record
	heads map[string]store.Record
}

func (m *mk) add(chain, typ string, at time.Time, payload map[string]any) {
	if m.heads == nil {
		m.heads = map[string]store.Record{}
	}
	pl, _ := json.Marshal(payload)
	h := m.heads[chain]
	r := store.Record{ID: typ + at.String(), Chain: chain, Seq: h.Seq + 1, Type: typ, ActorChain: json.RawMessage(`[{"id":"ops","kind":"human"}]`),
		Payload: pl, CreatedAt: at, PrevHash: h.Hash}
	r.Hash, _ = store.ComputeHash(&r)
	m.heads[chain] = r
	m.recs = append(m.recs, r)
}

func TestArt73SeriousIncidentDeadlines(t *testing.T) {
	aia, _ := Lookup("eu-ai-act", "")
	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	eval := func(m *mk) ControlResult {
		return control(Evaluate(aia, EvidenceFromRecords(m.recs, Scope{}, now)), "AIA-73")
	}
	m := &mk{}
	m.add("ops", "ledger.incident.serious", t0, map[string]any{"incident_id": "inc-1", "category": "health"})
	if c := eval(m); c.Status != Gap || !strings.Contains(c.Summary, "1 unreported") {
		t.Fatal(c.Summary)
	}
	m.add("ops", "ledger.incident.reported", t0.Add(3*24*time.Hour), map[string]any{"incident_id": "inc-1", "authority": "MSA-DE"})
	if c := eval(m); c.Status != Pass {
		t.Fatal(c.Summary)
	}
	// critical infrastructure: 2 days
	m.add("ops", "ledger.incident.serious", t0.Add(4*24*time.Hour), map[string]any{"incident_id": "inc-2", "category": "critical_infrastructure"})
	m.add("ops", "ledger.incident.reported", t0.Add(7*24*time.Hour), map[string]any{"incident_id": "inc-2"})
	if c := eval(m); c.Status != Gap || !strings.Contains(c.Summary, "1 reported after") {
		t.Fatal(c.Summary)
	}
	// no incidents recorded -> manual (absence is not evidence)
	if c := eval(&mk{}); c.Status != Manual {
		t.Fatal(c.Status)
	}
}

func signedReport(t *testing.T, s keys.Signer) Report {
	b := testfix.MultiProduct()
	tp, _ := Lookup("eu-ai-act", "")
	r := Evaluate(tp, EvidenceFromRecords(b.Recs, Scope{}, now))
	if err := Sign(context.Background(), &r, s); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSignVerifyAndRenderAllFormats(t *testing.T) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, s := range []keys.Signer{keys.Ed25519Signer{Key: ed}, keys.ECDSASigner{Key: ec}} {
		r := signedReport(t, s)
		if len(r.DocumentHash) != 64 || r.Signature == nil {
			t.Fatal("unsigned")
		}
		if err := Verify(r, nil); err != nil {
			t.Fatal(err)
		}
		if err := Verify(r, anchor.TrustSet{s.KeyID(): s.PublicKey()}); err != nil {
			t.Fatal(err)
		}
		if err := Verify(r, anchor.TrustSet{"ed25519:other": nil}); err == nil {
			t.Fatal("untrusted key accepted")
		}
		// JSON round trip still verifies; any edit breaks it
		var buf bytes.Buffer
		if err := WriteJSON(&buf, r); err != nil {
			t.Fatal(err)
		}
		var back Report
		if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
			t.Fatal(err)
		}
		if err := Verify(back, nil); err != nil {
			t.Fatalf("round trip: %v", err)
		}
		back.Controls[0].Status = Pass
		back.Controls[0].Summary = "all good"
		if err := Verify(back, nil); err == nil || !strings.Contains(err.Error(), "altered") {
			t.Fatalf("edited report verified: %v", err)
		}

		var html bytes.Buffer
		if err := WriteHTML(&html, r); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{r.DocumentHash, "Art. 19(1)", "Art. 73(2)-(4)", "Art. 26(6)", "Root-key rotation history", r.Signature.KeyID} {
			if !strings.Contains(html.String(), want) {
				t.Fatalf("html lacks %q", want)
			}
		}

		pdf, err := RenderPDF(r)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(pdf, []byte("%PDF-1.")) || !bytes.Contains(pdf, []byte("%%EOF")) {
			t.Fatal("not a PDF")
		}
		if !bytes.Contains(pdf, []byte(r.DocumentHash)) {
			t.Fatal("document hash not embedded in PDF metadata")
		}
		emb, err := ExtractFromPDF(pdf)
		if err != nil {
			t.Fatal(err)
		}
		if emb.DocumentHash != r.DocumentHash {
			t.Fatal("embedded report differs")
		}
		if err := Verify(emb, nil); err != nil {
			t.Fatalf("embedded report: %v", err)
		}
		// deterministic for the same report
		pdf2, _ := RenderPDF(r)
		if !bytes.Equal(pdf, pdf2) {
			t.Fatal("PDF output not deterministic")
		}
	}
}
