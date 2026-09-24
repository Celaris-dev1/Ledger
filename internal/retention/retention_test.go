package retention

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/keys"
	"github.com/Celaris-dev1/Ledger/internal/store"
	"github.com/Celaris-dev1/Ledger/internal/storetest"
)

func TestParseRetentionAndPolicy(t *testing.T) {
	for _, ok := range []string{"6y", "18m", "400d"} {
		if _, _, _, err := ParseRetention(ok); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, _, err := ParseRetention("6 years"); err == nil {
		t.Fatal("accepted")
	}
	t0 := time.Date(2020, 2, 29, 0, 0, 0, 0, time.UTC)
	if got := (Policy{MinRetention: "6y"}).Until(t0); got.Year() != 2026 {
		t.Fatal(got)
	}
	h := Hold{ID: "h", Chains: []string{"a"}, SubjectKeys: []string{"dk:1"}}
	if !h.Covers("a", "") || !h.Covers("", "dk:1") || h.Covers("b", "dk:2") {
		t.Fatal("covers")
	}
	h.Released = true
	if h.Covers("a", "") {
		t.Fatal("released hold covers")
	}
}

func appendSealed(t *testing.T, st *store.Store, ks keys.DataKeyStore, chain, subject, text string) {
	t.Helper()
	pl, _ := json.Marshal(map[string]string{"note": text})
	env, err := keys.Seal(ks, subject, chain, "clinic.note", pl)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Append(context.Background(), store.AppendRequest{Chain: chain, Type: "clinic.note",
		ActorChain: []store.Actor{{Kind: "human", ID: "dr-a"}}, Payload: env}); err != nil {
		t.Fatal(err)
	}
}

func TestEraseLifecycle(t *testing.T) {
	st := storetest.Open(t)
	ctx := context.Background()
	ks := &keys.FileDataKeyStore{Dir: t.TempDir()}
	now := time.Now().UTC()
	svc := &Service{Store: st, DataKeys: ks, Now: func() time.Time { return now }}

	appendSealed(t, st, ks, "clinic", "patient-1", "Jane Doe asthma")
	appendSealed(t, st, ks, "clinic", "patient-2", "John Roe flu")
	appendSealed(t, st, ks, "billing", "patient-1", "Jane Doe invoice")
	if _, err := st.Append(ctx, store.AppendRequest{Chain: "clinic", Type: "plain", ActorChain: []store.Actor{{Kind: "human", ID: "dr-a"}}, Payload: json.RawMessage(`{"x":1}`)}); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.SetPolicy(ctx, Policy{Chain: "clinic", Regime: "hipaa", MinRetention: "1y"}, "compliance-officer"); err == nil {
		t.Fatal("hipaa policy below 6y accepted")
	}
	if _, err := svc.SetPolicy(ctx, Policy{Chain: "clinic", Regime: "hipaa"}, "compliance-officer"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateHold(ctx, Hold{ID: "lit-1", Reason: "litigation Doe v. Clinic", Chains: []string{"billing"}}, "counsel"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateHold(ctx, Hold{ID: "lit-1", Reason: "dup", All: true}, "counsel"); err == nil {
		t.Fatal("duplicate hold id accepted")
	}

	req := EraseRequest{Subject: "patient-1", Reason: "data subject request #88", LegalBasis: "GDPR Art. 17", Operator: "dpo"}
	// 1. legal hold on billing blocks erasure
	if _, _, err := svc.Erase(ctx, req); !errors.Is(err, ErrLegalHold) {
		t.Fatalf("want legal hold, got %v", err)
	}
	if _, err := ks.Get(ks.KeyIDFor("patient-1")); err != nil {
		t.Fatal("key destroyed despite hold")
	}
	if _, err := svc.ReleaseHold(ctx, "lit-1", "case settled", "counsel"); err != nil {
		t.Fatal(err)
	}
	// 2. HIPAA minimum retention blocks without an override
	if _, _, err := svc.Erase(ctx, req); !errors.Is(err, ErrRetention) {
		t.Fatalf("want retention block, got %v", err)
	}
	// 3. with a recorded override the subject is crypto-shredded
	req.OverrideRetention = "records are duplicated in the EHR of record; payload not required for HIPAA documentation"
	rec, e, err := svc.Erase(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Chain != SystemChain || rec.Type != TypeErasure || e.RecordsAffected != 2 || strings.Join(e.Chains, ",") != "billing,clinic" {
		t.Fatalf("%+v %+v", rec, e)
	}
	if strings.Contains(string(rec.Payload), "patient-1") {
		t.Fatal("subject identifier leaked into the erasure record")
	}

	// every chain still verifies: nothing was edited or deleted
	for _, c := range []string{"clinic", "billing", SystemChain} {
		v, err := st.Verify(ctx, c)
		if err != nil || !v.OK {
			t.Fatalf("%s: %+v %v", c, v, err)
		}
	}
	var n int
	_ = st.Pool.QueryRow(ctx, `SELECT count(*) FROM records`).Scan(&n)
	if n != 4+4 { // 4 data records + policy, hold, release, erasure
		t.Fatalf("record count %d", n)
	}
	// plaintext is unrecoverable: not in the database, key gone from disk, decryption fails
	_ = st.Pool.QueryRow(ctx, `SELECT count(*) FROM records WHERE payload::text LIKE '%Jane%' OR payload::text LIKE '%John%'`).Scan(&n)
	if n != 0 {
		t.Fatal("plaintext stored in the database")
	}
	recs, _ := st.ChainRecords(ctx, "clinic")
	if _, err := keys.Open(ks, "clinic", "clinic.note", recs[0].Payload); !errors.Is(err, keys.ErrKeyDestroyed) {
		t.Fatalf("patient-1 still decryptable: %v", err)
	}
	if pt, err := keys.Open(ks, "clinic", "clinic.note", recs[1].Payload); err != nil || !strings.Contains(string(pt), "John") {
		t.Fatal("other subject affected")
	}
	files, _ := filepath.Glob(filepath.Join(ks.Dir, "*.key"))
	for _, f := range files {
		b, _ := os.ReadFile(f)
		if strings.Contains(f, strings.ReplaceAll(ks.KeyIDFor("patient-1"), ":", "_")) {
			t.Fatalf("key file remains: %s %d bytes", f, len(b))
		}
	}
	// append-only still enforced
	if _, err := st.Pool.Exec(ctx, `DELETE FROM records WHERE chain='clinic'`); err == nil {
		t.Fatal("delete allowed")
	}

	// state and status
	s, _ := svc.State(ctx)
	if len(s.Erasures) != 1 || len(s.ActiveHolds()) != 0 || s.Holds[0].ReleasedBy != "counsel" || s.Policies["clinic"].MinRetention != "6y" {
		t.Fatalf("%+v", s)
	}
	stat, err := svc.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, cs := range stat {
		if cs.Chain == "clinic" && (cs.Regime != "hipaa" || cs.PastRetention != 0 || cs.Records != 3) {
			t.Fatalf("%+v", cs)
		}
		if cs.Chain == "billing" && !cs.NoPolicyWarning {
			t.Fatalf("%+v", cs)
		}
	}
	// 7 years later the clinic records are past retention (eligible, never deleted)
	svc.Now = func() time.Time { return now.AddDate(7, 0, 0) }
	stat, _ = svc.Status(ctx)
	for _, cs := range stat {
		if cs.Chain == "clinic" && cs.PastRetention != 3 {
			t.Fatalf("%+v", cs)
		}
	}
	// a hold on a subject blocks that subject's erasure
	if _, err := svc.CreateHold(ctx, Hold{ID: "sub-hold", Reason: "regulator inquiry", SubjectKeys: []string{ks.KeyIDFor("patient-2")}}, "counsel"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Erase(ctx, EraseRequest{Subject: "patient-2", Reason: "r", Operator: "dpo", OverrideRetention: "x"}); !errors.Is(err, ErrLegalHold) {
		t.Fatalf("subject hold ignored: %v", err)
	}
}
