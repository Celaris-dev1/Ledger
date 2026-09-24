// Package anchor signs chain roots with Ed25519 and writes them out for external anchoring.
package anchor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/keys"
)

// Root is the signed chain root (GET /v1/chains/{chain}/root).
type Root struct {
	Chain     string `json:"chain"`
	Seq       int64  `json:"seq"`
	Head      string `json:"head"`
	Signature string `json:"signature"`
	PublicKey string `json:"public_key"`
	KeyID     string `json:"key_id,omitempty"` // KeyID(public key); not part of the signed message
	// Alg is the signature algorithm; empty means Ed25519 (every root before KMS support).
	// ECDSA roots ("ecdsa-p256-sha256", e.g. AWS KMS / Vault) carry a PKIX DER public key.
	Alg      string `json:"alg,omitempty"`
	SignedAt string `json:"signed_at,omitempty"`
}

// Message is the exact byte string that is signed.
func Message(chain string, seq int64, head string) []byte {
	return []byte(fmt.Sprintf("ledger-chain-root/v1\n%s\n%d\n%s", chain, seq, head))
}

// LoadKey resolves the signing key: LEDGER_SIGNING_KEY (base64 32-byte seed or 64-byte private key),
// else the key file at path (created with a fresh key, mode 0600, if missing).
func LoadKey(envVal, path string) (ed25519.PrivateKey, error) {
	if envVal != "" {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(envVal))
		if err != nil {
			return nil, fmt.Errorf("LEDGER_SIGNING_KEY: %w", err)
		}
		switch len(b) {
		case ed25519.SeedSize:
			return ed25519.NewKeyFromSeed(b), nil
		case ed25519.PrivateKeySize:
			return ed25519.PrivateKey(b), nil
		}
		return nil, errors.New("LEDGER_SIGNING_KEY must be base64 of a 32-byte seed or 64-byte key")
	}
	if path == "" {
		path = "ledger_ed25519.key"
	}
	if b, err := os.ReadFile(path); err == nil {
		return LoadKey(string(b), "")
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if dir := filepath.Dir(path); dir != "." {
		_ = os.MkdirAll(dir, 0o700)
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(priv.Seed())), 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}

// Sign produces a signed Root.
func Sign(key ed25519.PrivateKey, chain string, seq int64, head string) Root {
	sig := ed25519.Sign(key, Message(chain, seq, head))
	return Root{
		Chain: chain, Seq: seq, Head: head,
		Signature: base64.StdEncoding.EncodeToString(sig),
		PublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
		KeyID:     KeyID(key.Public().(ed25519.PublicKey)),
		SignedAt:  time.Now().UTC().Format(time.RFC3339),
	}
}

// SignWith produces a signed Root using any keys.Signer (file, Vault Transit, AWS KMS).
func SignWith(ctx context.Context, s keys.Signer, chain string, seq int64, head string) (Root, error) {
	sig, err := s.Sign(ctx, Message(chain, seq, head))
	if err != nil {
		return Root{}, err
	}
	r := Root{
		Chain: chain, Seq: seq, Head: head,
		Signature: base64.StdEncoding.EncodeToString(sig),
		PublicKey: base64.StdEncoding.EncodeToString(s.PublicKey()),
		KeyID:     s.KeyID(),
		SignedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	if s.Algorithm() != keys.AlgEd25519 {
		r.Alg = s.Algorithm()
	}
	return r, nil
}

// RootKeyID is the key id of the root's embedded public key for its algorithm.
func RootKeyID(r Root) string {
	pub, _ := base64.StdEncoding.DecodeString(r.PublicKey)
	return keys.KeyIDFor(keys.NormalizeAlg(r.Alg), pub)
}

// VerifyRoot checks a Root's signature against its embedded public key (Ed25519 or ECDSA P-256).
func VerifyRoot(r Root) bool {
	pub, err := base64.StdEncoding.DecodeString(r.PublicKey)
	if err != nil {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil {
		return false
	}
	return keys.VerifySignature(r.Alg, pub, Message(r.Chain, r.Seq, r.Head), sig) == nil
}

// Write writes the root to dir/<chain>/<seq>.json and dir/<chain>/latest.json. The directory is
// meant to be committed to a public repo or shipped to an external timestamping service.
func Write(dir string, r Root) (string, error) {
	safe := strings.Map(func(c rune) rune {
		if c == '/' || c == '\\' || c == '.' {
			return '_'
		}
		return c
	}, r.Chain)
	d := filepath.Join(dir, safe)
	if err := os.MkdirAll(d, 0o755); err != nil {
		return "", err
	}
	b, _ := json.MarshalIndent(r, "", "  ")
	p := filepath.Join(d, fmt.Sprintf("%010d.json", r.Seq))
	if err := os.WriteFile(p, b, 0o644); err != nil {
		return "", err
	}
	return p, os.WriteFile(filepath.Join(d, "latest.json"), b, 0o644)
}
