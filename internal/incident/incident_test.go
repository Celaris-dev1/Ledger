package incident

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/Celaris-dev1/Ledger/internal/store"
	"github.com/Celaris-dev1/Ledger/internal/testfix"
	"github.com/jackc/pgx/v5"
)

type fake struct{ b *testfix.Builder }

func (f fake) Chains(context.Context) ([]string, error) { return f.b.Chains(), nil }
func (f fake) ChainRecords(_ context.Context, c string) ([]store.Record, error) {
	return f.b.Chain(c), nil
}
func (f fake) Verify(_ context.Context, c string) (store.VerifyResult, error) {
	return store.VerifyRecords(c, f.b.Chain(c)), nil
}

func checkReport(t *testing.T, r *Report) {
	t.Helper()
	if r == nil {
		t.Fatal("no report")
	}
	chains := map[string]int{}
	for _, c := range r.Chains {
		chains[c.Chain] = c.Records
	}
	// harbour 7 + warrant 3 (2 via token_id without goal_id) + ledger 2 + gate 4 + proof 2 (via proof_run_id)
	want := map[string]int{"harbour": 7, "warrant": 3, "ledger": 2, "gate": 4, "proof": 2}
	for c, n := range want {
		if chains[c] != n {
			t.Errorf("chain %s: %d records in incident, want %d (%v)", c, chains[c], n, chains)
		}
	}
	if _, ok := chains["bench"]; ok {
		t.Error("unrelated bench record pulled in")
	}
	for _, e := range r.Narrative {
		if e.GoalID == "other-goal" {
			t.Error("unrelated goal pulled in")
		}
	}
	for i := 1; i < len(r.Narrative); i++ {
		if r.Narrative[i].At.Before(r.Narrative[i-1].At) {
			t.Fatal("narrative not ordered")
		}
	}
	if !r.Summary.AllChainsIntact || r.Summary.Records != 18 {
		t.Fatalf("summary: %+v", r.Summary)
	}
	if len(r.Effects) != 2 || !r.Effects[0].Committed || r.Effects[1].Committed || r.Effects[1].Status != "failed" {
		t.Fatalf("effects: %+v", r.Effects)
	}
	if r.Summary.Denials != 1 || r.Summary.FailedChecks != 2 {
		t.Fatalf("denials/failed: %+v", r.Summary)
	}
	var sawToken, sawDenied bool
	for _, a := range r.Authorisations {
		if strings.Contains(a.What, "tok-1 issued to planner-agent") && strings.HasPrefix(a.Who, "alice") {
			sawToken = true
		}
		if a.Decision == "denied" && strings.Contains(a.What, "git.push") {
			sawDenied = true
		}
	}
	if !sawToken || !sawDenied {
		t.Fatalf("authorisations: %+v", r.Authorisations)
	}
	linked := map[string]bool{}
	for _, e := range r.Narrative {
		linked[e.LinkedBy] = true
	}
	if !linked["token_id=tok-1"] || !linked["run_id=proof-run-9"] {
		t.Fatalf("cross-references not used: %v", linked)
	}
}

func TestIncidentMultiProduct(t *testing.T) {
	b := testfix.MultiProduct()
	r, err := Build(context.Background(), fake{b}, "goal-incident-7")
	if err != nil {
		t.Fatal(err)
	}
	checkReport(t, r)

	var h, m, j bytes.Buffer
	if err := WriteHTML(&h, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(h.String(), "<script>") || !strings.Contains(h.String(), "&lt;script&gt;") {
		t.Fatal("HTML not escaped")
	}
	if strings.Contains(h.String(), "http://") && strings.Contains(h.String(), "src=") {
		t.Fatal("HTML references external resources")
	}
	if err := WriteMarkdown(&m, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(m.String(), "<script>") || !strings.Contains(m.String(), "Who authorised what") {
		t.Fatalf("markdown: %s", m.String())
	}
	if err := WriteJSON(&j, r); err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(j.Bytes(), &back); err != nil || back.GoalID != "goal-incident-7" {
		t.Fatal(err)
	}
	if r, _ := Build(context.Background(), fake{b}, "nope"); r != nil {
		t.Fatal("report for unknown goal")
	}
}

func TestIncidentReportsBrokenChain(t *testing.T) {
	b := testfix.MultiProduct()
	for i := range b.Recs {
		if b.Recs[i].Type == "gate.run.decided" {
			b.Recs[i].Payload = json.RawMessage(`{"decision":"pass","run_id":"gate-run-3"}`)
		}
	}
	r, err := Build(context.Background(), fake{b}, "goal-incident-7")
	if err != nil {
		t.Fatal(err)
	}
	if r.Summary.AllChainsIntact {
		t.Fatal("tampered chain not reported")
	}
	for _, c := range r.Chains {
		if (c.Chain == "gate") == c.OK {
			t.Fatalf("chain status: %+v", c)
		}
	}
	var m bytes.Buffer
	_ = WriteMarkdown(&m, r)
	if !strings.Contains(m.String(), "FAILS verification") {
		t.Fatal("markdown hides broken chain")
	}
}

func TestMarkdownEscape(t *testing.T) {
	if got := md("a|b <img src=x> *x* [l](u)\n"); got != `a\|b &lt;img src=x&gt; \*x\* \[l\]\(u\) ` {
		t.Fatalf("%q", got)
	}
}

func TestIncidentPostgres(t *testing.T) {
	base := os.Getenv("LEDGER_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("LEDGER_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	var rb [4]byte
	_, _ = rand.Read(rb[:])
	schema := "ledger_test_" + hex.EncodeToString(rb[:])
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE") //nolint:errcheck
	u, _ := url.Parse(base)
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	st, err := store.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, r := range testfix.MultiProduct().Recs {
		if _, err := st.Append(ctx, testfix.Request(r)); err != nil {
			t.Fatal(err)
		}
	}
	r, err := Build(ctx, st, "goal-incident-7")
	if err != nil {
		t.Fatal(err)
	}
	checkReport(t, r)
}
