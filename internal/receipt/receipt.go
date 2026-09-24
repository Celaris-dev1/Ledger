// Package receipt implements the "stack-receipt/v1" envelope: a signed, product-agnostic
// record any of the stack's products (Gate, Proof, Ledger, Warrant, Harbour, Bench) can
// emit to attest to a decision, effect or verification, and that Ledger stores, verifies
// and links across products for the incident report.
//
// See docs/receipt-spec.md for the normative spec. This package is deliberately dependency-light
// (canon + keys only) so other repos can vendor/copy the same shape without pulling in Ledger's
// storage or server code.
package receipt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/canon"
	"github.com/Celaris-dev1/Ledger/internal/keys"
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func unb64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// Version is the only envelope version this package currently emits and accepts.
const Version = "stack-receipt/v1"

// Link points at another product's receipt or record that this receipt is evidence about
// or depends on (e.g. a Harbour effect linking to the Warrant token that authorised it).
type Link struct {
	Product string `json:"product"` // "gate" | "proof" | "ledger" | "warrant" | "harbour" | "bench"
	ID      string `json:"id"`      // that product's record/receipt id
	Hash    string `json:"hash"`    // that product's record/payload hash (hex sha256)
}

// Envelope is the stack-receipt/v1 wire format. Fields are ordered here for readability;
// the wire form is canonical JSON (object keys sorted), not struct field order.
type Envelope struct {
	Version   string `json:"version"`             // must be Version
	Product   string `json:"product"`              // emitting product, e.g. "gate"
	Kind      string `json:"kind"`                 // product-defined, e.g. "gate.verdict", "warrant.decision"
	GoalID    string `json:"goal_id,omitempty"`
	Actors    []Actor `json:"actor_chain"`
	Subject   string `json:"subject,omitempty"`     // what this receipt is about (run id, token id, effect id, ...)
	PayloadHash string `json:"payload_hash"`         // hex sha256 of the canonical payload this receipt attests to
	Links     []Link `json:"links,omitempty"`
	IssuedAt  time.Time `json:"issued_at"`
	SignerKeyID string `json:"signer_key_id"`
	Signature string `json:"signature"` // base64, Ed25519 over the canonical JSON of the envelope with this field = ""
}

// Actor mirrors the actor_chain element used across the stack (see Ledger's store.Actor).
type Actor struct {
	Kind         string `json:"kind"`
	ID           string `json:"id"`
	Model        string `json:"model,omitempty"`
	ModelVersion string `json:"model_version,omitempty"`
}

// PayloadHash returns hex sha256 of the canonical JSON of payload, for use as PayloadHash.
func PayloadHash(payload any) (string, error) {
	return canon.Hash("", payload)
}

// signingBytes returns the canonical JSON of env with Signature cleared: the exact bytes signed.
func signingBytes(env Envelope) ([]byte, error) {
	env.Signature = ""
	b, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	return canon.CanonicalBytes(b)
}

// Sign fills SignerKeyID and Signature on env using s. IssuedAt is set to now if zero.
func Sign(ctx context.Context, s keys.Signer, env Envelope) (Envelope, error) {
	if env.Version == "" {
		env.Version = Version
	}
	if env.IssuedAt.IsZero() {
		env.IssuedAt = time.Now().UTC()
	}
	if err := validateContent(env); err != nil {
		return Envelope{}, err
	}
	env.SignerKeyID = s.KeyID()
	msg, err := signingBytes(env)
	if err != nil {
		return Envelope{}, err
	}
	sig, err := s.Sign(ctx, msg)
	if err != nil {
		return Envelope{}, err
	}
	env.Signature = b64(sig)
	return env, nil
}

// Verify checks structure, that PayloadHash looks like hex sha256, and the Ed25519/ECDSA
// signature, given the trusted public key (raw 32 bytes Ed25519, or PKIX DER for ECDSA) and
// its algorithm. Callers that only trust a keyring by key id should look pub/alg up by
// env.SignerKeyID before calling Verify.
func Verify(env Envelope, alg string, pub []byte) error {
	if err := validateStructure(env); err != nil {
		return err
	}
	sig, err := unb64(env.Signature)
	if err != nil {
		return fmt.Errorf("receipt: malformed signature: %w", err)
	}
	if got := keys.KeyIDFor(keys.NormalizeAlg(alg), pub); got != env.SignerKeyID {
		return fmt.Errorf("receipt: signer_key_id %q does not match supplied key (%q)", env.SignerKeyID, got)
	}
	msg, err := signingBytes(env)
	if err != nil {
		return err
	}
	return keys.VerifySignature(alg, pub, msg, sig)
}

// validateContent checks every field except the signing fields (signer_key_id, signature),
// which are not yet known before Sign fills them in.
func validateContent(env Envelope) error {
	if env.Version != Version {
		return fmt.Errorf("receipt: unsupported version %q, want %q", env.Version, Version)
	}
	if env.Product == "" {
		return errors.New("receipt: product is required")
	}
	if !validProduct[env.Product] {
		return fmt.Errorf("receipt: unknown product %q", env.Product)
	}
	if env.Kind == "" {
		return errors.New("receipt: kind is required")
	}
	if len(env.Actors) == 0 || env.Actors[0].Kind != "human" {
		return errors.New("receipt: actor_chain must be non-empty and start with a human")
	}
	if len(env.PayloadHash) != 64 || !isHex(env.PayloadHash) {
		return errors.New("receipt: payload_hash must be 64 hex chars (sha256)")
	}
	for i, l := range env.Links {
		if l.Product == "" || !validProduct[l.Product] {
			return fmt.Errorf("receipt: links[%d].product invalid: %q", i, l.Product)
		}
		if l.ID == "" {
			return fmt.Errorf("receipt: links[%d].id is required", i)
		}
		if l.Hash != "" && (len(l.Hash) != 64 || !isHex(l.Hash)) {
			return fmt.Errorf("receipt: links[%d].hash must be 64 hex chars if present", i)
		}
	}
	if env.IssuedAt.IsZero() {
		return errors.New("receipt: issued_at is required")
	}
	return nil
}

// validateStructure checks the full envelope, including the signing fields; used by Verify.
func validateStructure(env Envelope) error {
	if err := validateContent(env); err != nil {
		return err
	}
	if env.SignerKeyID == "" {
		return errors.New("receipt: signer_key_id is required")
	}
	if env.Signature == "" {
		return errors.New("receipt: signature is required")
	}
	return nil
}

var validProduct = map[string]bool{
	"gate": true, "proof": true, "ledger": true, "warrant": true, "harbour": true, "bench": true,
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// SortLinks orders links deterministically (product, then id) for stable envelopes.
func SortLinks(links []Link) {
	sort.Slice(links, func(i, j int) bool {
		if links[i].Product != links[j].Product {
			return links[i].Product < links[j].Product
		}
		return links[i].ID < links[j].ID
	})
}
