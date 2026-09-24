package backup

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Celaris-dev1/Ledger/internal/storetest"
)

// Regression: restore inserted each record's payload text exactly as it appeared in the backup.
// Verification hashes canonical(text), so a crafted backup could carry equivalent-but-different
// JSON (here a duplicate key whose last value is the original) that verified while the restored
// row read "status":"pass" to any first-key-wins parser or a human looking at the UI.
func TestRestoreStoresCanonicalText(t *testing.T) {
	f := setup(t)
	gateFile := ""
	for _, c := range f.m.Chains {
		if c.Name == "gate" {
			gateFile = c.File
		}
	}
	dir := copyDir(t, f.dir)
	p := filepath.Join(dir, gateFile)
	b, _ := os.ReadFile(p)
	b2 := bytes.Replace(b, []byte(`"stage":"security","status":"fail"`), []byte(`"stage":"security","status":"pass","status":"fail"`), 1)
	if bytes.Equal(b, b2) {
		t.Fatal("fixture changed: security stage record not found")
	}
	_ = os.WriteFile(p, b2, 0o644)
	resign(t, dir, f.signer, nil) // an insider holding the backup key
	dst := storetest.Open(t)
	ctx := context.Background()
	if _, err := Restore(ctx, dst, dir, VerifyOptions{Trust: trustOf(f.kr)}); err != nil {
		t.Fatal(err)
	}
	recs, _ := dst.ChainRecords(ctx, "gate")
	for _, r := range recs {
		if bytes.Contains(r.Payload, []byte(`"pass","status"`)) {
			t.Fatalf("non-canonical payload restored verbatim: %s", r.Payload)
		}
	}
	if v, _ := dst.Verify(ctx, "gate"); !v.OK {
		t.Fatalf("restored chain does not verify: %+v", v)
	}
}
