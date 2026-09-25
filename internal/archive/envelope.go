package archive

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// EnvelopeFormat marks an archive-segment envelope (distinct from internal/keys' per-record
// envelope: this one wraps a whole sealed bundle, with the data key itself wrapped for the
// customer's KMS or local key, not derived per data-subject).
const EnvelopeFormat = "ledger-archive-envelope/v1"

// Envelope is what actually gets uploaded to S3 when archive encryption is enabled: an
// AES-256-GCM-encrypted bundle plus the data key needed to open it, itself wrapped so the
// object store never sees an unwrapped key.
type Envelope struct {
	Format     string `json:"ledger_archive_envelope"`
	Alg        string `json:"alg"`         // AES-256-GCM
	WrapAlg    string `json:"wrap_alg"`    // "local-key-file" today; see KeySource
	WrappedKey string `json:"wrapped_key"` // base64
	WrapNonce  string `json:"wrap_nonce,omitempty"`
	KeyID      string `json:"key_id,omitempty"` // identifies which customer key wrapped this
	Nonce      string `json:"nonce"`            // base64, for the segment ciphertext
	Ciphertext string `json:"ciphertext"`       // base64
}

// KeySource supplies the archive data-key-wrapping key ("customer KMS for the archive").
//
// Two modes are supported today:
//   - Local key file (LEDGER_ARCHIVE_KEY_FILE): a 32-byte AES-256 key the customer generates and
//     controls themselves, e.g. `openssl rand 32 -out archive.key`. Wrapping is AES-256-GCM
//     ("local-key-file"). This needs no network call and works entirely offline; it is the
//     recommended default when the customer does not already run Vault or AWS KMS.
//   - Ledger's existing signer/KMS abstraction (internal/keys, LEDGER_SIGNER=vault|awskms) is
//     deliberately NOT reused to wrap data keys here: internal/keys.Signer signs (Ed25519/ECDSA),
//     it does not expose an Encrypt/Decrypt (wrap/unwrap) operation, and Vault Transit's own
//     "encrypt" endpoint and AWS KMS's GenerateDataKey/Decrypt are different APIs than the
//     "sign" ones internal/keys.Signer wraps. Wiring either in is future work — see README.
//     Until then, customer KMS wrapping means the local key file.
type KeySource interface {
	// WrapID identifies the key (for the envelope's KeyID field / operator visibility).
	WrapID() string
	// Wrap encrypts a 32-byte data key, returning ciphertext, nonce and the wrap algorithm name.
	Wrap(dataKey []byte) (ciphertext, nonce []byte, alg string, err error)
	// Unwrap reverses Wrap.
	Unwrap(ciphertext, nonce []byte, alg string) ([]byte, error)
}

// LocalKeyFile is a KeySource backed by a 32-byte AES-256 key read from a file the customer
// generates and controls. It is the only KeySource Ledger implements out of the box.
type LocalKeyFile struct {
	Path string
	key  []byte
}

// LocalKeyFileFromEnv builds a LocalKeyFile from LEDGER_ARCHIVE_KEY_FILE, or returns ok=false if
// unset (archive encryption is optional: segments are then written as plain bundles).
func LocalKeyFileFromEnv(getenv func(string) string) (*LocalKeyFile, bool, error) {
	p := strings.TrimSpace(getenv("LEDGER_ARCHIVE_KEY_FILE"))
	if p == "" {
		return nil, false, nil
	}
	lk := &LocalKeyFile{Path: p}
	if err := lk.load(); err != nil {
		return nil, false, err
	}
	return lk, true, nil
}

func (l *LocalKeyFile) load() error {
	if l.key != nil {
		return nil
	}
	b, err := os.ReadFile(l.Path)
	if err != nil {
		return fmt.Errorf("archive: key file: %w", err)
	}
	k := strings.TrimSpace(string(b))
	raw, err := decodeKeyMaterial(k)
	if err != nil {
		return fmt.Errorf("archive: key file %s: %w", l.Path, err)
	}
	if len(raw) != 32 {
		return fmt.Errorf("archive: key file %s: want 32 bytes for AES-256, got %d", l.Path, len(raw))
	}
	l.key = raw
	return nil
}

func decodeKeyMaterial(s string) ([]byte, error) {
	// Accept raw 32-byte binary files or base64/hex text, whichever the customer generated.
	if b, err := hexDecode(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := b64Decode(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if len(s) == 32 {
		return []byte(s), nil
	}
	return nil, errors.New("could not parse as 32-byte hex, base64 or raw key material")
}

func (l *LocalKeyFile) WrapID() string { return "local-key-file:" + l.Path }

func (l *LocalKeyFile) Wrap(dataKey []byte) (ciphertext, nonce []byte, alg string, err error) {
	if err := l.load(); err != nil {
		return nil, nil, "", err
	}
	blk, err := aes.NewCipher(l.key)
	if err != nil {
		return nil, nil, "", err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, nil, "", err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, "", err
	}
	return gcm.Seal(nil, nonce, dataKey, nil), nonce, "local-key-file", nil
}

func (l *LocalKeyFile) Unwrap(ciphertext, nonce []byte, alg string) ([]byte, error) {
	if alg != "local-key-file" {
		return nil, fmt.Errorf("archive: unsupported wrap alg %q", alg)
	}
	if err := l.load(); err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(l.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Seal envelope-encrypts plaintext (a sealed bundle) with a fresh random AES-256-GCM data key,
// wrapping that data key with ks.
func Seal(ks KeySource, plaintext []byte) ([]byte, error) {
	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(dataKey)
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
	ct := gcm.Seal(nil, nonce, plaintext, []byte(EnvelopeFormat))

	wrapped, wrapNonce, alg, err := ks.Wrap(dataKey)
	if err != nil {
		return nil, fmt.Errorf("archive: wrap data key: %w", err)
	}
	env := Envelope{
		Format:     EnvelopeFormat,
		Alg:        "AES-256-GCM",
		WrapAlg:    alg,
		WrappedKey: b64Encode(wrapped),
		WrapNonce:  b64Encode(wrapNonce),
		KeyID:      ks.WrapID(),
		Nonce:      b64Encode(nonce),
		Ciphertext: b64Encode(ct),
	}
	return json.Marshal(env)
}

// Open reverses Seal.
func Open(ks KeySource, envelopeJSON []byte) ([]byte, error) {
	var env Envelope
	if err := json.Unmarshal(envelopeJSON, &env); err != nil {
		return nil, fmt.Errorf("archive: envelope: %w", err)
	}
	if env.Format != EnvelopeFormat {
		return nil, fmt.Errorf("archive: not an archive envelope (format %q)", env.Format)
	}
	wrapped, err := b64DecodeStrict(env.WrappedKey)
	if err != nil {
		return nil, err
	}
	wrapNonce, err := b64DecodeStrict(env.WrapNonce)
	if err != nil {
		return nil, err
	}
	dataKey, err := ks.Unwrap(wrapped, wrapNonce, env.WrapAlg)
	if err != nil {
		return nil, fmt.Errorf("archive: unwrap data key: %w", err)
	}
	nonce, err := b64DecodeStrict(env.Nonce)
	if err != nil {
		return nil, err
	}
	ct, err := b64DecodeStrict(env.Ciphertext)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, []byte(EnvelopeFormat))
}

// IsEnvelope reports whether data looks like a JSON archive envelope (vs. a plain bundle tar,
// which starts with the gzip magic bytes or a tar header — never '{').
func IsEnvelope(data []byte) bool {
	for _, b := range data {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		default:
			return b == '{'
		}
	}
	return false
}
