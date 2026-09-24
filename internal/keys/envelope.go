package keys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// EnvelopeFormat marks an encrypted payload.
const EnvelopeFormat = "ledger-envelope/v1"

// Envelope is the JSON that replaces a record payload when it is encrypted for a data subject.
// The record hash covers this envelope (i.e. the ciphertext), so chain verification never needs
// the key: after crypto-shredding every hash still verifies, the plaintext is simply gone.
//
// AAD binds the ciphertext to its key id and the record's chain/type, so an envelope cannot be
// replayed into a different chain or record type.
type Envelope struct {
	Format     string `json:"ledger_envelope"`
	Alg        string `json:"alg"` // AES-256-GCM
	KeyID      string `json:"key_id"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func aad(keyID, chain, typ string) []byte {
	return []byte(EnvelopeFormat + "\n" + keyID + "\n" + chain + "\n" + typ)
}

// Seal encrypts plaintext JSON for subject and returns the envelope as canonical-able JSON.
func Seal(ks DataKeyStore, subject, chain, typ string, plaintext []byte) (json.RawMessage, error) {
	id, key, err := ks.GetOrCreate(subject)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, aad(id, chain, typ))
	return json.Marshal(Envelope{Format: EnvelopeFormat, Alg: "AES-256-GCM", KeyID: id,
		Nonce: base64.StdEncoding.EncodeToString(nonce), Ciphertext: base64.StdEncoding.EncodeToString(ct)})
}

// ParseEnvelope returns the envelope if payload is one.
func ParseEnvelope(payload []byte) (*Envelope, bool) {
	if !bytes.Contains(payload, []byte(EnvelopeFormat)) {
		return nil, false
	}
	var e Envelope
	if err := json.Unmarshal(payload, &e); err != nil || e.Format != EnvelopeFormat {
		return nil, false
	}
	return &e, true
}

// Open decrypts an envelope payload. It returns ErrKeyDestroyed after crypto-shredding.
func Open(ks DataKeyStore, chain, typ string, payload []byte) ([]byte, error) {
	e, ok := ParseEnvelope(payload)
	if !ok {
		return nil, errors.New("envelope: payload is not encrypted")
	}
	key, err := ks.Get(e.KeyID)
	if err != nil {
		return nil, err
	}
	nonce, err1 := base64.StdEncoding.DecodeString(e.Nonce)
	ct, err2 := base64.StdEncoding.DecodeString(e.Ciphertext)
	if err := errors.Join(err1, err2); err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("envelope: bad nonce")
	}
	return gcm.Open(nil, nonce, ct, aad(e.KeyID, chain, typ))
}
