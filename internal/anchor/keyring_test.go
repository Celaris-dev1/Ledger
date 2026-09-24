package anchor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKeyringRotation(t *testing.T) {
	dir := t.TempDir()
	kr, err := OpenKeyring(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	oldID := kr.ActiveID()
	oldRoot := Sign(kr.Active, "c", 3, "h3")
	if oldRoot.KeyID != oldID {
		t.Fatalf("key id %q", oldRoot.KeyID)
	}
	base := TrustSet{oldID: kr.Public[oldID]}
	rot, err := kr.Rotate(false)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRotation(rot); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, fileID(oldID)+".key")); !os.IsNotExist(err) {
		t.Fatal("old private key not removed")
	}
	// reopen: new key active, old public still known
	kr2, err := OpenKeyring(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if kr2.ActiveID() != rot.NewKeyID || len(kr2.IDs()) != 2 {
		t.Fatalf("reopened keyring %v active %s", kr2.IDs(), kr2.ActiveID())
	}
	newRoot := Sign(kr2.Active, "c", 4, "h4")
	trust, errs := TrustFromRotations(base, []Rotation{rot})
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	for _, r := range []Root{oldRoot, newRoot} {
		if err := VerifyRootTrusted(r, trust); err != nil {
			t.Fatalf("%s: %v", r.KeyID, err)
		}
	}
	if err := VerifyRootTrusted(newRoot, base); err == nil {
		t.Fatal("new key trusted without rotation record")
	}
	// forged rotation (signed by an unknown key) is not trusted
	other, _ := OpenKeyring(t.TempDir(), nil)
	forged, _ := other.Rotate(true)
	if _, errs := TrustFromRotations(base, []Rotation{forged}); len(errs) != 1 {
		t.Fatal("forged rotation accepted")
	}
	rot.NewPublicKey = forged.NewPublicKey
	if VerifyRotation(rot) == nil {
		t.Fatal("tampered rotation verified")
	}
}

func TestLoadSignerImportsLegacyKey(t *testing.T) {
	dir := t.TempDir()
	legacy, err := LoadKey("", filepath.Join(dir, "legacy.key"))
	if err != nil {
		t.Fatal(err)
	}
	k, kr, err := LoadSigner("", filepath.Join(dir, "legacy.key"), filepath.Join(dir, "ring"))
	if err != nil || kr == nil || !k.Equal(legacy) {
		t.Fatalf("legacy key not imported: %v", err)
	}
}
