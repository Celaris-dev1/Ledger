package anchoring

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

// testStore opens a store in a throwaway schema. Skips unless LEDGER_TEST_DATABASE_URL is set.
func testStore(t *testing.T) *store.Store {
	t.Helper()
	base := os.Getenv("LEDGER_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("LEDGER_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	var b [4]byte
	_, _ = rand.Read(b[:])
	schema := "ledger_test_" + hex.EncodeToString(b[:])
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(base)
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	s, err := store.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Close()
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
		admin.Close(ctx)
	})
	return s
}

func appendN(t *testing.T, st *store.Store, chain string, from, to int) {
	t.Helper()
	for i := from; i <= to; i++ {
		_, err := st.Append(context.Background(), store.AppendRequest{Chain: chain, Type: "gate.run.enforced",
			ActorChain: []store.Actor{{Kind: "human", ID: "alice"}}, Payload: json.RawMessage(fmt.Sprintf(`{"amount":%d}`, i*100))})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// rewriteHistory is what a malicious DB admin does: disable the append-only trigger, edit a record,
// recompute every later hash and the head pointer so the chain is internally consistent again.
func rewriteHistory(t *testing.T, st *store.Store, chain string, seq int64, payload string) {
	t.Helper()
	ctx := context.Background()
	recs, err := st.ChainRecords(ctx, chain)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := st.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `ALTER TABLE records DISABLE TRIGGER records_append_only`); err != nil {
		t.Fatal(err)
	}
	prev := ""
	for i := range recs {
		r := &recs[i]
		if r.Seq == seq {
			r.Payload = json.RawMessage(payload)
		}
		if r.Seq >= seq {
			r.PrevHash = prev
			if r.Hash, err = store.ComputeHash(r); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `UPDATE records SET payload=$1, prev_hash=$2, hash=$3 WHERE id=$4`, string(r.Payload), r.PrevHash, r.Hash, r.ID); err != nil {
				t.Fatal(err)
			}
		}
		prev = r.Hash
	}
	if _, err := tx.Exec(ctx, `UPDATE chains SET head_hash=$1 WHERE name=$2`, prev, chain); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `ALTER TABLE records ENABLE TRIGGER records_append_only`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestEndToEndRewriteDetection(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	ca, _, tb := fakeTSAs(t, 3)
	tb.Quorum = 2
	tmp := t.TempDir()
	bare := filepath.Join(tmp, "anchors.git")
	if out, err := exec.Command("git", "init", "--quiet", "--bare", "-b", "main", bare).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	kr, err := anchor.OpenKeyring(filepath.Join(tmp, "keys"), nil)
	if err != nil {
		t.Fatal(err)
	}
	gitWork := filepath.Join(tmp, "gitwork")
	svc := &Service{Store: st, Key: kr.Active, Keyring: kr, Quorum: 2,
		Backends: []Backend{&FileBackend{Dir: filepath.Join(tmp, "dir")}, &GitBackend{Remote: bare, WorkDir: gitWork}, tb},
		Verifier: Verifier{TSARoots: ca.Pool(), GitDir: gitWork},
		RootDirs: []string{filepath.Join(tmp, "dir"), filepath.Join(gitWork, "roots")},
		Log:      log.New(os.Stderr, "", 0)}
	sched := &Scheduler{Svc: svc, EveryN: 3}

	const chain = "gate/runs"
	appendN(t, st, chain, 1, 2)
	if done, _ := sched.Tick(ctx); len(done) != 0 {
		t.Fatal("anchored before N records")
	}
	appendN(t, st, chain, 3, 5)
	done, err := sched.Tick(ctx)
	if err != nil || len(done) != 1 || done[0].Seq != 5 || len(done[0].Receipts) != 5 { // file + git + 3 TSAs
		t.Fatalf("tick: %v %+v", err, done)
	}

	// rotate the signing key; the rotation is a record in the `ledger` system chain
	rot, rec, err := svc.RotateKey(ctx, "alice", false)
	if err != nil || rec.Chain != SystemChain || rec.Type != RotationType {
		t.Fatalf("rotate: %v %+v", err, rec)
	}
	appendN(t, st, chain, 6, 8)
	// only gate/runs is due (3 new); the system chain has 1 record < N
	if done, _ := sched.Tick(ctx); len(done) != 1 || done[0].KeyID != rot.NewKeyID {
		t.Fatalf("tick after rotation: %+v", done)
	}

	// receipts table is append-only
	if _, err := st.Pool.Exec(ctx, `UPDATE anchor_receipts SET head='x'`); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("receipt update allowed: %v", err)
	}

	// a fresh verifier process: keyring reopened from disk (old key now public-only)
	kr2, err := anchor.OpenKeyring(filepath.Join(tmp, "keys"), nil)
	if err != nil {
		t.Fatal(err)
	}
	svc.Keyring = kr2
	rep, err := svc.VerifyChainAnchors(ctx, chain)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK || rep.Rewritten || rep.LastAnchored != 8 {
		t.Fatalf("clean: %s", FormatReport(rep))
	}
	keys := map[string]bool{}
	for _, c := range rep.Checks {
		keys[c.KeyID] = true
	}
	if !keys[rot.OldKeyID] || !keys[rot.NewKeyID] {
		t.Fatalf("expected roots from both keys: %v", keys)
	}

	// --- the attack ---
	rewriteHistory(t, st, chain, 2, `{"amount":1}`)
	if v, _ := st.Verify(ctx, chain); !v.OK {
		t.Fatalf("plain verify should be fooled by a full rehash: %+v", v)
	}
	rep, err = svc.VerifyChainAnchors(ctx, chain)
	if err != nil {
		t.Fatal(err)
	}
	txt := FormatReport(rep)
	t.Log("\n" + txt)
	if rep.OK || !rep.Rewritten || !strings.Contains(txt, "HISTORY REWRITTEN") || !strings.Contains(txt, "(0, 5]") {
		t.Fatalf("rewrite not detected:\n%s", txt)
	}

	// the admin also deletes every DB receipt: the git/dir witnesses still catch it
	if _, err := st.Pool.Exec(ctx, `ALTER TABLE anchor_receipts DISABLE TRIGGER USER; DELETE FROM anchor_receipts; ALTER TABLE anchor_receipts ENABLE TRIGGER USER`); err != nil {
		t.Fatal(err)
	}
	rep, _ = svc.VerifyChainAnchors(ctx, chain)
	if !rep.Rewritten {
		t.Fatalf("external witnesses missed rewrite:\n%s", FormatReport(rep))
	}

	// ChainAnchors (API payload)
	v, err := svc.ChainAnchors(ctx, chain, true)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(v); !strings.Contains(string(b), `"rewritten":true`) {
		t.Fatalf("api payload: %s", b)
	}
}
