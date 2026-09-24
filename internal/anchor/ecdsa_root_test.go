package anchor

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/Celaris-dev1/Ledger/internal/keys"
)

// Roots signed by KMS/Vault ECDSA keys and legacy Ed25519 roots both verify, and trust sets
// can hold either kind.
func TestMixedAlgorithmRoots(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	ctx := context.Background()
	ecRoot, err := SignWith(ctx, keys.ECDSASigner{Key: ec}, "gate", 5, "h5")
	if err != nil {
		t.Fatal(err)
	}
	edRoot, _ := SignWith(ctx, keys.Ed25519Signer{Key: ed}, "gate", 5, "h5")
	if edRoot.Alg != "" || edRoot.KeyID != KeyID(ed.Public().(ed25519.PublicKey)) {
		t.Fatal("ed25519 roots must stay in the legacy format")
	}
	if ecRoot.Alg != keys.AlgECDSAP256 {
		t.Fatal(ecRoot.Alg)
	}
	for _, r := range []Root{ecRoot, edRoot, Sign(ed, "gate", 5, "h5")} {
		if !VerifyRoot(r) {
			t.Fatalf("root %s did not verify", r.KeyID)
		}
		bad := r
		bad.Head = "h6"
		if VerifyRoot(bad) {
			t.Fatal("tampered root verified")
		}
	}
	der, _ := base64.StdEncoding.DecodeString(ecRoot.PublicKey)
	trust := TrustSet{ecRoot.KeyID: der}
	if err := VerifyRootTrusted(ecRoot, trust); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRootTrusted(edRoot, trust); err == nil {
		t.Fatal("untrusted ed25519 root accepted")
	}
	// algorithm confusion: claiming ed25519 for an ECDSA root fails
	conf := ecRoot
	conf.Alg = ""
	if VerifyRoot(conf) {
		t.Fatal("alg confusion accepted")
	}
}
