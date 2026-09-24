package anchor

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

var fuzzKey = ed25519.NewKeyFromSeed(make([]byte, 32))

// FuzzVerifyRootJSON: any root JSON that verifies against the (single) trusted key must attest
// exactly a (chain, seq, head) that key actually signed.
func FuzzVerifyRootJSON(f *testing.F) {
	signed := map[[3]string]bool{}
	add := func(chain string, seq int64, head string) {
		r := Sign(fuzzKey, chain, seq, head)
		b, _ := json.Marshal(r)
		f.Add(b)
		signed[[3]string{r.Chain, fmt.Sprint(r.Seq), r.Head}] = true
	}
	add("gate", 7, "ab12")
	add("a\n1", 2, "h") // Message ambiguity probe: same bytes as ("a", 1, "2\nh")
	add("t/acme/x", 1, "00ff")
	forged := Sign(fuzzKey, "a\n1", 2, "h")
	forged.Chain, forged.Seq, forged.Head = "a", 1, "2\nh"
	fb, _ := json.Marshal(forged)
	f.Add(fb)
	trust := TrustSet{KeyID(fuzzKey.Public().(ed25519.PublicKey)): fuzzKey.Public().(ed25519.PublicKey)}
	f.Fuzz(func(t *testing.T, b []byte) {
		var r Root
		if json.Unmarshal(b, &r) != nil {
			return
		}
		if VerifyRootTrusted(r, trust) != nil {
			return
		}
		if !signed[[3]string{r.Chain, fmt.Sprint(r.Seq), r.Head}] {
			t.Fatalf("forged root verified: chain=%q seq=%d head=%q", r.Chain, r.Seq, r.Head)
		}
	})
}

// FuzzVerifyRotation: a rotation statement verifies only as signed.
func FuzzVerifyRotation(f *testing.F) {
	// deterministic keys so every fuzz worker sees the same statement
	newKey := ed25519.NewKeyFromSeed(append(make([]byte, 31), 1))
	oldPub, newPub := fuzzKey.Public().(ed25519.PublicKey), newKey.Public().(ed25519.PublicKey)
	rot := Rotation{OldKeyID: KeyID(oldPub), OldPublicKey: base64.StdEncoding.EncodeToString(oldPub),
		NewKeyID: KeyID(newPub), NewPublicKey: base64.StdEncoding.EncodeToString(newPub), RotatedAt: "2026-09-24T00:00:00Z"}
	msg := RotationMessage(rot.OldKeyID, rot.NewKeyID, rot.NewPublicKey, rot.RotatedAt)
	rot.CrossSig = base64.StdEncoding.EncodeToString(ed25519.Sign(fuzzKey, msg))
	rot.NewKeySig = base64.StdEncoding.EncodeToString(ed25519.Sign(newKey, msg))
	b, _ := json.Marshal(rot)
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		var r Rotation
		if json.Unmarshal(b, &r) != nil || VerifyRotation(r) != nil {
			return
		}
		if r.OldKeyID != rot.OldKeyID || r.NewKeyID != rot.NewKeyID || r.RotatedAt != rot.RotatedAt {
			t.Fatalf("forged rotation verified: %+v", r)
		}
		trust, errs := TrustFromRotations(TrustSet{rot.OldKeyID: fuzzKey.Public().(ed25519.PublicKey)}, []Rotation{r})
		if len(errs) != 0 || len(trust) != 2 {
			t.Fatalf("trust: %v %v", trust, errs)
		}
	})
}
