//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/anchor/tsa/tsatest"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

// anchoringEnv wires three fake RFC 3161 TSAs (one of them refusing: 2-of-3 must still anchor),
// a local bare git repository, a keyring and the scheduler (every 3 records, polled fast).
func anchoringEnv(t *testing.T) (*Env, []*tsatest.TSA) {
	t.Helper()
	e := NewEnv(t)
	ca := tsatest.NewCA("e2e-tsa-root")
	var tsas []*tsatest.TSA
	var urls []string
	for i := 0; i < 3; i++ {
		ts := tsatest.New(ca, fmt.Sprintf("tsa%d", i))
		t.Cleanup(ts.Close)
		tsas = append(tsas, ts)
		urls = append(urls, fmt.Sprintf("tsa%d=%s", i, ts.URL()))
	}
	tsas[2].Set(func(t *tsatest.TSA) { t.Reject = true }) // one TSA down: quorum 2 of 3
	remote := filepath.Join(e.Dir, "anchors-remote.git")
	if out, err := exec.Command("git", "init", "--quiet", "--bare", "-b", "main", remote).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	return e.With(
		"LEDGER_TSA_URLS", strings.Join(urls, ","),
		"LEDGER_TSA_TRUST", ca.WriteBundle(e.Dir, "tsa-roots.pem"),
		"LEDGER_TSA_QUORUM", "2",
		"LEDGER_ANCHOR_GIT_REMOTE", remote,
		"LEDGER_ANCHOR_GIT_DIR", filepath.Join(e.Dir, "anchors-clone"),
		"LEDGER_ANCHOR_GIT_BRANCH", "main",
		"LEDGER_KEYRING_DIR", filepath.Join(e.Dir, "keyring"),
		"LEDGER_ANCHOR_EVERY", "3",
		"LEDGER_ANCHOR_POLL", "200ms",
		"GIT_AUTHOR_NAME", "ledger-e2e", "GIT_AUTHOR_EMAIL", "e2e@ledger.invalid",
		"GIT_COMMITTER_NAME", "ledger-e2e", "GIT_COMMITTER_EMAIL", "e2e@ledger.invalid",
	), tsas
}

func appendPayments(t *testing.T, d *Daemon, from, n int) {
	t.Helper()
	for i := from; i < from+n; i++ {
		d.Append("", map[string]any{"chain": "payments", "type": "ledger.budget.charged", "goal_id": "g-pay",
			"actor_chain": []Actor{human("cfo"), agent("payer")}, "payload": map[string]any{"resource": "usd", "amount": 100 + i}})
	}
}

// waitAnchored waits until the scheduler has stored receipts covering seq >= minSeq whose
// witnesses include both quorum TSAs and git.
func waitAnchored(t *testing.T, d *Daemon, minSeq int64) []map[string]any {
	t.Helper()
	var anchors []map[string]any
	eventually(t, 30*time.Second, func() string {
		r := d.Do("GET", "/v1/chains/payments/anchors", "", nil)
		if r.Status != 200 {
			return fmt.Sprintf("anchors: %d %s", r.Status, r.Body)
		}
		var body struct {
			Anchors []map[string]any `json:"anchors"`
		}
		_ = json.Unmarshal(r.Body, &body)
		anchors = body.Anchors
		kinds := map[string]bool{}
		for _, a := range anchors {
			if num(a["seq"]) >= minSeq {
				kinds[str(a["backend"])+":"+str(a["name"])] = true
				kinds[str(a["backend"])] = true
			}
		}
		if !kinds["git"] || !strings.Contains(fmt.Sprint(kinds), "tsa0") || !strings.Contains(fmt.Sprint(kinds), "tsa1") {
			return fmt.Sprintf("no git+tsa0+tsa1 receipts at seq>=%d yet: %v\n%s", minSeq, kinds, r.Body)
		}
		return ""
	})
	return anchors
}

func TestAnchoringRewriteAttackAndKeyRotation(t *testing.T) {
	e, _ := anchoringEnv(t)
	d := e.Start()
	appendPayments(t, d, 0, 6)
	waitAnchored(t, d, 6)
	if r := d.Do("GET", "/v1/chains/payments/anchors?verify=1", "", nil); r.Status != 200 || strings.Contains(string(r.Body), `"ok":false`) {
		t.Fatalf("anchors?verify=1: %d %s", r.Status, r.Body)
	}
	if out, _, code := e.Ledger("verify", "--anchors"); code != 0 {
		t.Fatalf("verify --anchors before rotation: exit %d\n%s", code, out)
	}
	if log, err := exec.Command("git", "--git-dir", e.Vars["LEDGER_ANCHOR_GIT_REMOTE"], "log", "--name-only", "--format=%s", "main").CombinedOutput(); err != nil || !strings.Contains(string(log), "roots/payments/") {
		t.Fatalf("bare repo has no pushed roots: %v\n%s", err, log)
	}

	// Key rotation, then more records anchored under the new key.
	keysBefore := e.MustLedger("keys", "list")
	rot := e.MustLedger("keys", "rotate", "--operator", "sec-officer")
	if !strings.Contains(rot, "rotated") {
		t.Fatalf("rotate: %s", rot)
	}
	keysAfter := e.MustLedger("keys", "list")
	if strings.Count(keysAfter, "\n") != strings.Count(keysBefore, "\n")+1 {
		t.Fatalf("keyring did not grow:\n%s\n->\n%s", keysBefore, keysAfter)
	}
	newKey := strings.Fields(strings.SplitN(rot, "-> ", 2)[1])[0]
	d.Restart() // README: restart ledgerd after a rotation
	appendPayments(t, d, 6, 6)
	anchors := waitAnchored(t, d, 12)
	sawNew := false
	for _, a := range anchors {
		if num(a["seq"]) >= 12 && strings.Contains(string(mustJSON(a)), newKey) {
			sawNew = true
		}
	}
	if !sawNew {
		t.Fatalf("no receipt at seq>=12 signed by the rotated key %s: %s", newKey, mustJSON(anchors))
	}
	if out, _, code := e.Ledger("verify", "--anchors"); code != 0 {
		t.Fatalf("verify --anchors after rotation: exit %d\n%s", code, out)
	}
	d.Stop()

	// The rewrite attack: a superuser disables the append-only trigger, edits seq 4's amount,
	// recomputes every later hash and the head pointer — all through psql.
	e.PSQL(rewriteSQL(t, e, "payments", 4, `{"amount":1,"resource":"usd"}`))
	out, _, code := e.Ledger("verify", "--chain", "payments")
	if code != 0 || !strings.Contains(out, "OK") {
		t.Fatalf("plain verify must pass after a consistent rewrite (that is the point of anchoring): exit %d\n%s", code, out)
	}
	out, _, code = e.Ledger("verify", "--anchors", "--chain", "payments")
	if code != 1 {
		t.Fatalf("verify --anchors must fail after the rewrite: exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "HISTORY REWRITTEN") || !regexp.MustCompile(`seq range \(\d+, \d+\]`).MatchString(out) {
		t.Fatalf("verify --anchors does not name the rewritten range:\n%s", out)
	}
	m := regexp.MustCompile(`seq range \((\d+), (\d+)\]`).FindStringSubmatch(out)
	var lo, hi int
	fmt.Sscan(m[1], &lo)
	fmt.Sscan(m[2], &hi)
	if !(lo < 4 && hi >= 4) {
		t.Fatalf("rewritten range (%d, %d] does not contain the edited seq 4:\n%s", lo, hi, out)
	}
	// The JSON report too.
	jout, _, _ := e.Ledger("verify", "--anchors", "--chain", "payments", "--json")
	if !strings.Contains(jout, `"ok": false`) {
		t.Fatalf("--json report: %s", jout)
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// rewriteSQL builds the attacker's psql script: the new payload for seq and forged hashes for
// every record from seq on, plus the chain head.
func rewriteSQL(t *testing.T, e *Env, chain string, seq int64, payload string) string {
	t.Helper()
	so := e.PSQL(fmt.Sprintf(`SELECT json_agg(json_build_object('id',id,'chain',chain,'seq',seq,'type',type,'goal_id',coalesce(goal_id,''),
	  'actor_chain',actor_chain::text,'policy_version',coalesce(policy_version,''),'payload',payload::text,
	  'created_at',to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'prev_hash',prev_hash,'hash',hash) ORDER BY seq)
	  FROM records WHERE chain='%s'`, chain))
	var rows []struct {
		ID            string `json:"id"`
		Chain         string `json:"chain"`
		Type          string `json:"type"`
		GoalID        string `json:"goal_id"`
		ActorChain    string `json:"actor_chain"`
		PolicyVersion string `json:"policy_version"`
		Payload       string `json:"payload"`
		CreatedAt     string `json:"created_at"`
		PrevHash      string `json:"prev_hash"`
		Hash          string `json:"hash"`
		Seq           int64  `json:"seq"`
	}
	dec := json.NewDecoder(strings.NewReader(so))
	if err := dec.Decode(&rows); err != nil {
		t.Fatalf("decoding records: %v\n%s", err, so)
	}
	var sql strings.Builder
	sql.WriteString("BEGIN;\nALTER TABLE records DISABLE TRIGGER USER;\n")
	prev := ""
	for _, r := range rows {
		if r.Seq == seq {
			r.Payload = payload
		}
		if r.Seq >= seq {
			ts, err := time.Parse(time.RFC3339Nano, r.CreatedAt)
			if err != nil {
				t.Fatal(err)
			}
			rec := &store.Record{ID: r.ID, Chain: r.Chain, Seq: r.Seq, Type: r.Type, GoalID: r.GoalID,
				ActorChain: json.RawMessage(r.ActorChain), PolicyVersion: r.PolicyVersion, Payload: json.RawMessage(r.Payload),
				CreatedAt: ts, PrevHash: prev}
			h, err := store.ComputeHash(rec)
			if err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(&sql, "UPDATE records SET payload='%s', prev_hash='%s', hash='%s' WHERE id='%s';\n",
				strings.ReplaceAll(r.Payload, "'", "''"), prev, h, r.ID)
			r.Hash = h
		}
		prev = r.Hash
	}
	fmt.Fprintf(&sql, "UPDATE chains SET head_hash='%s' WHERE name='%s';\nALTER TABLE records ENABLE TRIGGER USER;\nCOMMIT;\n", prev, chain)
	return sql.String()
}
