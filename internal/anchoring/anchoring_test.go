package anchoring

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/anchor/tsa"
	"github.com/Celaris-dev1/Ledger/internal/anchor/tsa/tsatest"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

func memChain(chain string, n int, payload func(i int) string) []store.Record {
	var out []store.Record
	prev := ""
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 1; i <= n; i++ {
		r := store.Record{ID: fmt.Sprintf("00000000-0000-0000-0000-%012d", i), Chain: chain, Seq: int64(i), Type: "t",
			ActorChain: json.RawMessage(`[{"id":"alice","kind":"human"}]`), Payload: json.RawMessage(payload(i)),
			CreatedAt: t0.Add(time.Duration(i) * time.Second), PrevHash: prev}
		r.Hash, _ = store.ComputeHash(&r)
		prev = r.Hash
		out = append(out, r)
	}
	return out
}

func key(t *testing.T) ed25519.PrivateKey {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// receiptsFor anchors (chain, seq, head) through backends and returns the rows as they would be stored.
func receiptsFor(t *testing.T, k ed25519.PrivateKey, rec store.Record, bs ...Backend) []StoredReceipt {
	t.Helper()
	root := anchor.Sign(k, rec.Chain, rec.Seq, rec.Hash)
	subj := NewSubject(root)
	var out []StoredReceipt
	for _, b := range bs {
		rs, err := b.Anchor(context.Background(), subj)
		if err != nil {
			t.Fatalf("%s: %v", b.Name(), err)
		}
		for _, r := range rs {
			out = append(out, StoredReceipt{Chain: rec.Chain, Seq: rec.Seq, Head: rec.Hash, RootDigest: subj.DigestHex(),
				KeyID: root.KeyID, RootJSON: string(subj.RootJSON), Backend: r.Backend, Kind: r.Kind, Receipt: r.Bytes,
				Meta: r.Meta, AnchoredAt: r.AnchoredAt})
		}
	}
	return out
}

func fakeTSAs(t *testing.T, n int) (*tsatest.CA, []*tsatest.TSA, *TSABackend) {
	ca := tsatest.NewCA("Ledger Test TSA Root")
	b := &TSABackend{Quorum: n}
	var fs []*tsatest.TSA
	for i := 0; i < n; i++ {
		f := tsatest.New(ca, fmt.Sprintf("tsa-%d", i))
		t.Cleanup(f.Close)
		fs = append(fs, f)
		b.Clients = append(b.Clients, &tsa.Client{Name: fmt.Sprintf("tsa%d", i), URL: f.URL(), Opt: tsa.Options{Roots: ca.Pool()}})
	}
	return ca, fs, b
}

func TestTSAQuorum(t *testing.T) {
	_, fs, b := fakeTSAs(t, 3)
	b.Quorum = 2
	subj := NewSubject(anchor.Sign(key(t), "c", 1, "h"))
	fs[2].Set(func(f *tsatest.TSA) { f.WrongImprint = true })
	recs, err := b.Anchor(context.Background(), subj)
	var pe *PartialError
	if len(recs) != 2 || err == nil || !errors.As(err, &pe) {
		t.Fatalf("want 2 receipts + partial error, got %d, %v", len(recs), err)
	}
	fs[1].Set(func(f *tsatest.TSA) { f.Reject = true })
	recs, err = b.Anchor(context.Background(), subj)
	if len(recs) != 1 || err == nil || !strings.Contains(err.Error(), "quorum not met: 1 of 3") {
		t.Fatalf("want quorum failure, got %d, %v", len(recs), err)
	}
}

func TestVerifyChainDetectsRewrite(t *testing.T) {
	ca, _, tb := fakeTSAs(t, 2)
	k := key(t)
	dir := t.TempDir()
	orig := memChain("c", 6, func(i int) string { return fmt.Sprintf(`{"n":%d}`, i) })
	var rcpts []StoredReceipt
	rcpts = append(rcpts, receiptsFor(t, k, orig[2], tb, &FileBackend{Dir: dir})...)
	rcpts = append(rcpts, receiptsFor(t, k, orig[5], tb, &FileBackend{Dir: dir})...)
	trust := anchor.TrustSet{anchor.KeyID(k.Public().(ed25519.PublicKey)): k.Public().(ed25519.PublicKey)}
	opt := Options{Verifier: Verifier{TSARoots: ca.Pool()}, Trust: trust, Quorum: 2}

	rep := VerifyChain("c", orig, rcpts, opt)
	if !rep.OK || rep.Rewritten || rep.LastAnchored != 6 || len(rep.Checks) != 6 {
		t.Fatalf("clean chain: %s", FormatReport(rep))
	}

	// Rewrite record 5 and rehash everything after it: internally consistent, so plain verify passes.
	rewritten := memChain("c", 7, func(i int) string {
		if i == 5 {
			return `{"n":"EDITED"}`
		}
		return fmt.Sprintf(`{"n":%d}`, i)
	})
	if v := store.VerifyRecords("c", rewritten); !v.OK {
		t.Fatal("rehashed chain should pass plain verify")
	}
	rep = VerifyChain("c", rewritten, rcpts, opt)
	if rep.OK || !rep.Rewritten || !rep.ChainIntact {
		t.Fatalf("rewrite not detected: %s", FormatReport(rep))
	}
	if !strings.Contains(rep.Findings[0], "(3, 6]") {
		t.Fatalf("range: %s", FormatReport(rep))
	}
	// external dir copies catch it too, even with every DB receipt deleted
	ext, err := ScanRootDir(dir, "c")
	if err != nil || len(ext) != 2 {
		t.Fatalf("scan: %v %d", err, len(ext))
	}
	if rep := VerifyChain("c", rewritten, ext, opt); !rep.Rewritten {
		t.Fatalf("external roots missed rewrite: %s", FormatReport(rep))
	}
	// truncation
	if rep := VerifyChain("c", orig[:4], rcpts, opt); !rep.Rewritten || !strings.Contains(FormatReport(rep), "truncated") {
		t.Fatalf("truncation: %s", FormatReport(rep))
	}
}

func TestVerifyChainRejectsForgedReceipts(t *testing.T) {
	ca, _, tb := fakeTSAs(t, 1)
	k := key(t)
	recs := memChain("c", 3, func(i int) string { return `{}` })
	good := receiptsFor(t, k, recs[2], tb)[0]
	trust := anchor.TrustSet{anchor.KeyID(k.Public().(ed25519.PublicKey)): k.Public().(ed25519.PublicKey)}
	opt := Options{Verifier: Verifier{TSARoots: ca.Pool()}, Trust: trust}

	// admin rewrites the receipt row's head to match a rewritten chain: signature/imprint catch it
	forged := good
	forged.Head = "deadbeef"
	// admin re-signs with their own key: untrusted
	evil := key(t)
	resigned := good
	resigned.RootJSON = string(anchor.MarshalRoot(anchor.Sign(evil, "c", 3, recs[2].Hash)))
	// token bytes corrupted
	corrupt := good
	corrupt.Receipt = append([]byte(nil), good.Receipt...)
	corrupt.Receipt[len(corrupt.Receipt)-5] ^= 1
	// token for a different root: wrong imprint
	other := receiptsFor(t, k, recs[1], tb)[0]
	swapped := good
	swapped.Receipt = other.Receipt

	for name, r := range map[string]StoredReceipt{"forged-head": forged, "resigned": resigned, "corrupt": corrupt, "swapped": swapped} {
		rep := VerifyChain("c", recs, []StoredReceipt{r}, opt)
		if rep.OK || rep.Checks[0].Status != StatusInvalid {
			t.Errorf("%s: %s", name, FormatReport(rep))
		}
	}
	// without a trust bundle, TSA receipts are unverifiable (not silently OK)
	rep := VerifyChain("c", recs, []StoredReceipt{good}, Options{Trust: trust})
	if rep.Checks[0].Status != StatusUnverifiable {
		t.Fatalf("want unverifiable: %s", FormatReport(rep))
	}
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestGitBackendAgainstBareRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	tmp := t.TempDir()
	bare := filepath.Join(tmp, "anchors.git")
	git(t, tmp, "init", "--quiet", "--bare", "-b", "main", bare)
	b := &GitBackend{Remote: bare, WorkDir: filepath.Join(tmp, "work")}
	k := key(t)
	recs := memChain("gate/runs", 4, func(i int) string { return `{}` })
	r1 := receiptsFor(t, k, recs[1], b)
	r2 := receiptsFor(t, k, recs[3], b)
	var m struct {
		Commit, Path string
		Pushed       bool
	}
	_ = json.Unmarshal(r2[0].Meta, &m)
	if !m.Pushed || m.Path != "roots/gate_runs/0000000004.json" {
		t.Fatalf("meta %s", r2[0].Meta)
	}
	if got := git(t, bare, "rev-parse", "main"); got != m.Commit {
		t.Fatalf("bare repo main=%s, receipt commit=%s", got, m.Commit)
	}
	if got := git(t, bare, "show", m.Commit+":"+m.Path); got != strings.TrimSpace(r2[0].RootJSON) {
		t.Fatal("committed bytes differ")
	}
	// a second clone (e.g. an auditor's) verifies both receipts offline
	aud := filepath.Join(tmp, "auditor")
	git(t, tmp, "clone", "--quiet", bare, aud)
	opt := Options{Verifier: Verifier{GitDir: aud}}
	rep := VerifyChain("gate/runs", recs, append(r1, r2...), opt)
	if !rep.OK {
		t.Fatalf("%s", FormatReport(rep))
	}
	// receipt pointing at a commit the auditor does not have
	bad := r2[0]
	bad.Meta = json.RawMessage(`{"commit":"0000000000000000000000000000000000000000","path":"roots/x.json"}`)
	if rep := VerifyChain("gate/runs", recs, []StoredReceipt{bad}, opt); rep.Checks[0].Status != StatusInvalid {
		t.Fatalf("missing commit accepted: %s", FormatReport(rep))
	}
	// the auditor's clone of roots/ is itself an external witness
	ext, _ := ScanRootDir(filepath.Join(aud, "roots"), "gate/runs")
	if len(ext) != 2 {
		t.Fatalf("scan clone: %d", len(ext))
	}
}

func TestConfigFromEnv(t *testing.T) {
	ca := tsatest.NewCA("r")
	bundle := ca.WriteBundle(t.TempDir(), "tsa.pem")
	env := map[string]string{
		"LEDGER_TSA_URLS": "freetsa=https://freetsa.org/tsr, digicert=http://timestamp.digicert.com,http://timestamp.sectigo.com",
		"LEDGER_TSA_TRUST": bundle, "LEDGER_TSA_QUORUM": "2", "LEDGER_ANCHOR_INTERVAL": "1h", "LEDGER_ANCHOR_EVERY": "100",
		"LEDGER_ANCHOR_DIR": "/tmp/x",
	}
	c, err := ConfigFromEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if len(c.TSAs) != 3 || c.TSAs[2].Name != "tsa3" || c.TSAQuorum != 2 || c.Interval != time.Hour || c.EveryN != 100 || len(c.Backends()) != 2 {
		t.Fatalf("%+v", c)
	}
	delete(env, "LEDGER_TSA_TRUST")
	if _, err := ConfigFromEnv(func(k string) string { return env[k] }); err == nil {
		t.Fatal("TSAs without trust bundle accepted")
	}
}
