package backup

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
)

const fuzzBase = "testdata/fuzzbase"

// TestRegenBackupFixture rewrites testdata/fuzzbase (a genuine signed backup) from a live
// database. Only with LEDGER_REGEN_BACKUP_FIXTURE=1.
func TestRegenBackupFixture(t *testing.T) {
	if os.Getenv("LEDGER_REGEN_BACKUP_FIXTURE") != "1" {
		t.Skip("set LEDGER_REGEN_BACKUP_FIXTURE=1 (and LEDGER_TEST_DATABASE_URL) to regenerate")
	}
	f := setup(t)
	_ = os.RemoveAll(fuzzBase)
	if err := os.CopyFS(filepath.Join(fuzzBase, "bk"), os.DirFS(f.dir)); err != nil {
		t.Fatal(err)
	}
	tr := map[string]string{}
	for id, p := range f.kr.Public {
		tr[id] = base64.StdEncoding.EncodeToString(p)
	}
	b, _ := json.MarshalIndent(tr, "", "  ")
	if err := os.WriteFile(filepath.Join(fuzzBase, "trust.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

type fuzzBackup struct {
	files map[string][]byte // rel path -> bytes
	names []string
	trust anchor.TrustSet
	m     Manifest
}

func loadFuzzBackup(t testing.TB) fuzzBackup {
	fb := fuzzBackup{files: map[string][]byte{}, trust: anchor.TrustSet{}}
	root := filepath.Join(fuzzBase, "bk")
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		b, err := os.ReadFile(p)
		fb.files[filepath.ToSlash(rel)] = b
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for n := range fb.files {
		fb.names = append(fb.names, n)
	}
	sort.Strings(fb.names)
	var tr map[string]string
	b, err := os.ReadFile(filepath.Join(fuzzBase, "trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(b, &tr)
	for id, p := range tr {
		fb.trust[id], _ = base64.StdEncoding.DecodeString(p)
	}
	_ = json.Unmarshal(fb.files["manifest.json"], &fb.m)
	return fb
}

func (fb fuzzBackup) write(t *testing.T, override map[string][]byte) string {
	dir := t.TempDir()
	for n, b := range fb.files {
		if o, ok := override[n]; ok {
			if o == nil {
				continue // deleted
			}
			b = o
		}
		p := filepath.Join(dir, filepath.FromSlash(n))
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for n, b := range override {
		if _, ok := fb.files[n]; !ok && b != nil && filepath.IsLocal(n) {
			p := filepath.Join(dir, filepath.FromSlash(n))
			_ = os.MkdirAll(filepath.Dir(p), 0o755)
			_ = os.WriteFile(p, b, 0o644)
		}
	}
	return dir
}

// FuzzBackupLoad: any edit to a genuine signed backup (a byte change, insertion, truncation
// or deletion in any file, an extra file) is rejected by Load, except edits of manifest.json
// that leave its decoded content unchanged. Nothing panics.
func FuzzBackupLoad(f *testing.F) {
	fb := loadFuzzBackup(f)
	f.Add(uint8(0), uint8(0), uint32(10), byte('x'), []byte(nil))
	f.Add(uint8(1), uint8(2), uint32(100), byte(0), []byte(" "))
	f.Add(uint8(5), uint8(4), uint32(0), byte(0), []byte("{}"))
	f.Fuzz(func(t *testing.T, which, op uint8, pos uint32, val byte, ins []byte) {
		if _, err := Load(fb.write(t, nil), VerifyOptions{Trust: fb.trust}); err != nil {
			t.Fatalf("genuine backup rejected: %v", err)
		}
		name := fb.names[int(which)%len(fb.names)]
		orig := fb.files[name]
		var mut []byte
		switch op % 6 {
		case 0: // set a byte
			if len(orig) == 0 {
				return
			}
			mut = append([]byte(nil), orig...)
			mut[int(pos)%len(orig)] = val
		case 1: // insert
			p := int(pos) % (len(orig) + 1)
			mut = append(append(append([]byte(nil), orig[:p]...), ins...), orig[p:]...)
		case 2: // truncate
			mut = append([]byte(nil), orig[:int(pos)%(len(orig)+1)]...)
		case 3: // delete the file
			mut = nil
		case 4: // add an unlisted file
			if _, err := Load(fb.write(t, map[string][]byte{"chains/extra-" + string(rune('a'+val%26)) + ".jsonl": ins}), VerifyOptions{Trust: fb.trust}); err == nil {
				t.Fatal("unlisted file accepted")
			}
			return
		case 5: // replace the file wholesale
			mut = ins
		}
		if mut != nil && bytes.Equal(mut, orig) {
			return
		}
		L, err := Load(fb.write(t, map[string][]byte{name: mut}), VerifyOptions{Trust: fb.trust})
		if err != nil {
			return
		}
		if name == "manifest.json" && mut != nil {
			var m Manifest
			if json.Unmarshal(mut, &m) == nil && reflect.DeepEqual(m, fb.m) {
				return // re-encoded manifest with identical content
			}
		}
		t.Fatalf("altered backup accepted (%s, op %d): %d chains", name, op%6, len(L.Chains))
	})
}
