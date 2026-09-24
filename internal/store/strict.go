package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Celaris-dev1/Ledger/internal/canon"
)

// NonCanonicalError reports a stored record whose actor_chain or payload text is not the
// canonical form that was hashed. The hash covers canonical(stored text), so equivalent but
// different text (duplicate keys such as {"ok":false,"ok":true}, whitespace, key order) would
// otherwise verify while displaying, or being read by another parser as, something else.
// Append and restore only ever store canonical text, so in the database this only fires on
// tampering.
type NonCanonicalError struct{ Field string }

func (e *NonCanonicalError) Error() string {
	return fmt.Sprintf("stored %s is not in canonical form (record text altered)", e.Field)
}

// CheckCanonical returns a *NonCanonicalError when r's stored JSON fields are not
// byte-identical to their canonical encoding.
func CheckCanonical(r *Record) error {
	for _, f := range []struct {
		name string
		raw  []byte
	}{{"actor_chain", r.ActorChain}, {"payload", r.Payload}} {
		c, err := canon.CanonicalBytes(f.raw)
		if err != nil {
			return fmt.Errorf("%s: %w", f.name, err)
		}
		if !bytes.Equal(c, f.raw) {
			return &NonCanonicalError{Field: f.name}
		}
	}
	return nil
}

// hashStrict is ComputeHash plus, when strict, CheckCanonical.
func hashStrict(r *Record, strict bool) (string, error) {
	if strict {
		if err := CheckCanonical(r); err != nil {
			return "", err
		}
	}
	return ComputeHash(r)
}

func verifyReason(err error) string {
	var nc *NonCanonicalError
	if errors.As(err, &nc) {
		return nc.Error()
	}
	return "undecodable record: " + err.Error()
}

// CheckDuplicateKeys rejects JSON containing an object with a repeated key. Duplicate keys are
// resolved differently by different parsers (Go and JavaScript keep the last, others the
// first), so a payload like {"approved":false,"approved":true} would mean different things to
// different readers of the same evidence.
func CheckDuplicateKeys(raw []byte) error {
	d := newDupDecoder(raw)
	return d.value()
}

// ConflictError marks a request that conflicts with stored state (HTTP 409).
type ConflictError struct{ Msg string }

func (e *ConflictError) Error() string { return e.Msg }

// envelopeMarker identifies an encrypted payload (keys.EnvelopeFormat; not imported to keep
// store free of the keys package). Envelopes use a fresh nonce per seal, so a retried
// encrypted append never has byte-identical ciphertext and its payload is not compared.
const envelopeMarker = `"ledger_envelope":"ledger-envelope/v1"`

// sameRequest reports whether an idempotent retry describes the record already stored under
// its key. Returning the stored record for a different request would silently drop evidence.
func sameRequest(ex *Record, req *AppendRequest, ac, pl []byte) bool {
	if ex.Type != req.Type || ex.GoalID != req.GoalID || ex.PolicyVersion != req.PolicyVersion || !bytes.Equal(ex.ActorChain, ac) {
		return false
	}
	if bytes.Contains(ex.Payload, []byte(envelopeMarker)) && bytes.Contains(pl, []byte(envelopeMarker)) {
		return true
	}
	return bytes.Equal(ex.Payload, pl)
}

type dupDecoder struct{ dec *json.Decoder }

func newDupDecoder(raw []byte) *dupDecoder {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	return &dupDecoder{dec: d}
}

func (d *dupDecoder) value() error {
	tok, err := d.dec.Token()
	if err != nil {
		return err
	}
	switch tok {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.dec.More() {
			k, err := d.dec.Token()
			if err != nil {
				return err
			}
			ks, _ := k.(string)
			if seen[ks] {
				return fmt.Errorf("duplicate object key %q", ks)
			}
			seen[ks] = true
			if err := d.value(); err != nil {
				return err
			}
		}
		_, err = d.dec.Token()
		return err
	case json.Delim('['):
		for d.dec.More() {
			if err := d.value(); err != nil {
				return err
			}
		}
		_, err = d.dec.Token()
		return err
	}
	return nil
}
