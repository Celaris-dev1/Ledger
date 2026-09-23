// Package canon implements the Ledger canonical JSON encoding and record hash.
//
// canonical JSON = object keys sorted, no insignificant whitespace, no HTML escaping.
// hash = sha256hex(prev_hash + "\n" + canonical_json(record_without_hash_fields)).
package canon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Normalize decodes arbitrary JSON bytes preserving number literals so they can be re-encoded canonically.
func Normalize(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// Marshal encodes v canonically. Go's encoder sorts map keys; we disable HTML escaping.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// CanonicalBytes returns the canonical form of raw JSON bytes.
func CanonicalBytes(raw []byte) ([]byte, error) {
	v, err := Normalize(raw)
	if err != nil {
		return nil, err
	}
	return Marshal(v)
}

// Hash computes sha256hex(prev + "\n" + canonical(body)).
func Hash(prev string, body any) (string, error) {
	// round-trip through Normalize so struct/map inputs are treated identically
	b, err := Marshal(body)
	if err != nil {
		return "", err
	}
	c, err := CanonicalBytes(b)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte("\n"))
	h.Write(c)
	return hex.EncodeToString(h.Sum(nil)), nil
}
