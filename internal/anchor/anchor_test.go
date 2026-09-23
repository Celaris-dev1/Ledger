package anchor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSignVerifyWrite(t *testing.T) {
	dir := t.TempDir()
	key, err := LoadKey("", filepath.Join(dir, "k"))
	if err != nil {
		t.Fatal(err)
	}
	key2, _ := LoadKey("", filepath.Join(dir, "k"))
	if !key.Equal(key2) {
		t.Fatal("key file not reused")
	}
	r := Sign(key, "gate", 3, "abc")
	if !VerifyRoot(r) {
		t.Fatal("signature did not verify")
	}
	r2 := r
	r2.Head = "abd"
	if VerifyRoot(r2) {
		t.Fatal("tampered root verified")
	}
	p, err := Write(filepath.Join(dir, "anchors"), r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal(err)
	}
}
