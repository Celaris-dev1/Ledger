package anchoring

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
)

// Regression (hardening): git receipt meta comes from the audited database; a commit value
// starting with "-" became a `git show` option (--output=FILE writes a file on the verifier).
func TestGitReceiptMetaCannotInjectOptions(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	repo := t.TempDir()
	for _, args := range [][]string{{"init", "-q"}, {"-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "--allow-empty", "-m", "x"}} {
		if out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	root := anchor.Sign(key, "c", 1, "ab")
	subj := NewSubject(root)
	victim := filepath.Join(t.TempDir(), "written")
	for _, m := range []map[string]string{
		{"commit": "--output=" + victim, "path": "x"},
		{"commit": "HEAD", "path": "-x"},
		{"commit": "abcdef1", "path": "--output=" + victim},
	} {
		mb, _ := json.Marshal(m)
		_, err := Verifier{GitDir: repo}.VerifyReceipt(Receipt{Kind: KindGit, Bytes: subj.RootJSON, Meta: mb}, subj)
		if err == nil || !strings.Contains(err.Error(), "malformed") {
			t.Errorf("%v: want malformed error, got %v", m, err)
		}
	}
	if _, err := os.Stat(victim); err == nil {
		t.Fatal("git wrote a file chosen by receipt meta")
	}
}

// FuzzCheckReceipt: stored receipt rows (as read back from the database or an anchor dir)
// never panic the checker, and a row only checks OK when it carries the genuinely signed root.
func FuzzCheckReceipt(f *testing.F) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	root := anchor.Sign(key, "c", 1, "ab")
	rj := string(anchor.MarshalRoot(root))
	f.Add(rj, rj, int64(1), "ab", "file")
	f.Add(rj, `{}`, int64(1), "ab", "git")
	f.Add(`{"chain":"c","seq":1,"head":"ab"}`, rj, int64(0), "", "rfc3161")
	trust := anchor.TrustSet{anchor.KeyID(key.Public().(ed25519.PublicKey)): key.Public().(ed25519.PublicKey)}
	f.Fuzz(func(t *testing.T, rootJSON, receipt string, seq int64, head, kind string) {
		recs := memChain("c", 3, func(i int) string { return `{}` })
		sr := StoredReceipt{Chain: "c", Seq: seq, Head: head, RootJSON: rootJSON, Kind: kind, Receipt: []byte(receipt)}
		c := checkReceipt(sr, recs, Options{Trust: trust})
		if c.Valid {
			var got anchor.Root
			if json.Unmarshal([]byte(rootJSON), &got) != nil || got.Chain != "c" || got.Seq != 1 || got.Head != "ab" {
				t.Fatalf("receipt valid for a root that was never signed: %q", rootJSON)
			}
		}
	})
}
