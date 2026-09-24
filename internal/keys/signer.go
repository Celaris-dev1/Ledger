// Package keys abstracts where Ledger's keys live.
//
//   - Signer: signs chain roots and document hashes (auditor packs, backups). Implementations:
//     local Ed25519 (the existing key file / keyring), HashiCorp Vault Transit (Ed25519 or
//     ECDSA P-256) and AWS KMS (ECDSA P-256; KMS has no Ed25519 signing).
//   - DataKeyStore: per-subject AES-256 data keys for payload envelope encryption and
//     crypto-shredding. Implementation: local directory (FileDataKeyStore).
//
// Verification never needs the signer: VerifySignature handles both algorithms from the
// public key and algorithm name alone, so offline verifiers work for every backend.
package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// Algorithms.
const (
	AlgEd25519   = "ed25519"
	AlgECDSAP256 = "ecdsa-p256-sha256" // ASN.1 DER signature over sha256(message)
)

// Signer signs messages with a root key held somewhere (file, Vault, KMS).
type Signer interface {
	// Algorithm is AlgEd25519 or AlgECDSAP256.
	Algorithm() string
	// PublicKey is the encoded public key: raw 32 bytes for Ed25519, PKIX DER for ECDSA.
	PublicKey() []byte
	// KeyID is a stable id derived from the public key (see KeyIDFor).
	KeyID() string
	// Sign signs msg (the full message; ECDSA signers hash it with SHA-256).
	Sign(ctx context.Context, msg []byte) ([]byte, error)
}

// KeyIDFor derives the key id: "ed25519:"+hex(sha256(pub)[:8]) (unchanged from the keyring)
// or "ecdsa-p256:"+hex(sha256(pkix)[:8]).
func KeyIDFor(alg string, pub []byte) string {
	h := sha256.Sum256(pub)
	if alg == AlgECDSAP256 {
		return "ecdsa-p256:" + hex.EncodeToString(h[:8])
	}
	return "ed25519:" + hex.EncodeToString(h[:8])
}

// NormalizeAlg maps "" (legacy roots, which carry no alg) to Ed25519.
func NormalizeAlg(alg string) string {
	if alg == "" {
		return AlgEd25519
	}
	return alg
}

// VerifySignature verifies sig over msg for either algorithm.
func VerifySignature(alg string, pub, msg, sig []byte) error {
	switch NormalizeAlg(alg) {
	case AlgEd25519:
		if len(pub) != ed25519.PublicKeySize {
			return errors.New("ed25519 public key must be 32 bytes")
		}
		if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
			return errors.New("ed25519 signature invalid")
		}
		return nil
	case AlgECDSAP256:
		k, err := ParseECDSAPublic(pub)
		if err != nil {
			return err
		}
		d := sha256.Sum256(msg)
		if !ecdsa.VerifyASN1(k, d[:], sig) {
			return errors.New("ecdsa signature invalid")
		}
		return nil
	}
	return fmt.Errorf("unsupported signature algorithm %q", alg)
}

// ParseECDSAPublic parses a PKIX DER P-256 public key.
func ParseECDSAPublic(der []byte) (*ecdsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("ecdsa public key: %w", err)
	}
	ek, ok := k.(*ecdsa.PublicKey)
	if !ok || ek.Curve.Params().Name != "P-256" {
		return nil, errors.New("public key is not ECDSA P-256")
	}
	return ek, nil
}

// Signature is a detached signature with everything needed to verify it offline.
type Signature struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"` // base64
	Signature string `json:"signature"`  // base64
}

// SignDetached signs msg and packages the result.
func SignDetached(ctx context.Context, s Signer, msg []byte) (Signature, error) {
	sig, err := s.Sign(ctx, msg)
	if err != nil {
		return Signature{}, err
	}
	return Signature{Algorithm: s.Algorithm(), KeyID: s.KeyID(),
		PublicKey: base64.StdEncoding.EncodeToString(s.PublicKey()),
		Signature: base64.StdEncoding.EncodeToString(sig)}, nil
}

// Verify checks a detached signature (and that key_id matches the public key).
func (s Signature) Verify(msg []byte) error {
	pub, err1 := base64.StdEncoding.DecodeString(s.PublicKey)
	sig, err2 := base64.StdEncoding.DecodeString(s.Signature)
	if err := errors.Join(err1, err2); err != nil {
		return fmt.Errorf("malformed signature: %w", err)
	}
	if s.KeyID != "" && s.KeyID != KeyIDFor(NormalizeAlg(s.Algorithm), pub) {
		return errors.New("key_id does not match public key")
	}
	return VerifySignature(s.Algorithm, pub, msg, sig)
}

// Ed25519Signer is the local (file / keyring) signer.
type Ed25519Signer struct{ Key ed25519.PrivateKey }

func (s Ed25519Signer) Algorithm() string { return AlgEd25519 }
func (s Ed25519Signer) PublicKey() []byte { return []byte(s.Key.Public().(ed25519.PublicKey)) }
func (s Ed25519Signer) KeyID() string     { return KeyIDFor(AlgEd25519, s.PublicKey()) }
func (s Ed25519Signer) Sign(_ context.Context, msg []byte) ([]byte, error) {
	return ed25519.Sign(s.Key, msg), nil
}

// ECDSASigner is a local ECDSA P-256 signer (used in tests and for file-held ECDSA keys).
type ECDSASigner struct{ Key *ecdsa.PrivateKey }

func (s ECDSASigner) Algorithm() string { return AlgECDSAP256 }
func (s ECDSASigner) PublicKey() []byte {
	b, _ := x509.MarshalPKIXPublicKey(&s.Key.PublicKey)
	return b
}
func (s ECDSASigner) KeyID() string { return KeyIDFor(AlgECDSAP256, s.PublicKey()) }
func (s ECDSASigner) Sign(_ context.Context, msg []byte) ([]byte, error) {
	d := sha256.Sum256(msg)
	return ecdsa.SignASN1(randReader, s.Key, d[:])
}
