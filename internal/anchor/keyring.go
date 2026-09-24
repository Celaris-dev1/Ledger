package anchor

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// KeyID derives a stable identifier from an Ed25519 public key: "ed25519:" + first 16 hex of sha256(pub).
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(h[:8])
}

// Keyring holds the active signing key and every public key that has ever signed roots.
//
// On disk (LEDGER_KEYRING_DIR):
//
//	active                 key id of the active key
//	<id>.key               base64 seed of a key that can sign (0600); only the active key normally has one
//	<id>.pub               base64 public key (kept for every key, including retired ones)
//
// Retired keys keep verifying; they just stop signing.
type Keyring struct {
	Dir    string
	Active ed25519.PrivateKey
	Public map[string]ed25519.PublicKey
}

func fileID(id string) string { return strings.ReplaceAll(id, ":", "_") }

// OpenKeyring loads dir. If dir holds no keys, it is initialised with seed (if non-nil) or a fresh key.
func OpenKeyring(dir string, seed ed25519.PrivateKey) (*Keyring, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	kr := &Keyring{Dir: dir, Public: map[string]ed25519.PublicKey{}}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("keyring: bad public key %s", e.Name())
		}
		kr.Public[KeyID(pub)] = pub
	}
	active, err := os.ReadFile(filepath.Join(dir, "active"))
	if errors.Is(err, os.ErrNotExist) {
		if seed == nil {
			if _, seed, err = ed25519.GenerateKey(rand.Reader); err != nil {
				return nil, err
			}
		}
		if err := kr.install(seed); err != nil {
			return nil, err
		}
		return kr, nil
	} else if err != nil {
		return nil, err
	}
	id := strings.TrimSpace(string(active))
	priv, err := LoadKey("", filepath.Join(dir, fileID(id)+".key"))
	if err != nil {
		return nil, err
	}
	if KeyID(priv.Public().(ed25519.PublicKey)) != id {
		return nil, fmt.Errorf("keyring: active key file does not match id %s", id)
	}
	kr.Active = priv
	kr.Public[id] = priv.Public().(ed25519.PublicKey)
	return kr, nil
}

func (kr *Keyring) install(priv ed25519.PrivateKey) error {
	pub := priv.Public().(ed25519.PublicKey)
	id := KeyID(pub)
	base := filepath.Join(kr.Dir, fileID(id))
	if err := os.WriteFile(base+".key", []byte(base64.StdEncoding.EncodeToString(priv.Seed())), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(base+".pub", []byte(base64.StdEncoding.EncodeToString(pub)), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(kr.Dir, "active"), []byte(id), 0o600); err != nil {
		return err
	}
	kr.Active, kr.Public[id] = priv, pub
	return nil
}

// ActiveID is the key id of the signing key.
func (kr *Keyring) ActiveID() string { return KeyID(kr.Active.Public().(ed25519.PublicKey)) }

// IDs lists all known key ids, sorted.
func (kr *Keyring) IDs() []string {
	var out []string
	for id := range kr.Public {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Rotation describes a key rotation; it is recorded as a `ledger.key.rotated` record in the
// `ledger` system chain. CrossSig is the OLD key's signature over RotationMessage, so the new
// key's authority is provable from the old one.
type Rotation struct {
	OldKeyID     string `json:"old_key_id"`
	OldPublicKey string `json:"old_public_key"`
	NewKeyID     string `json:"new_key_id"`
	NewPublicKey string `json:"new_public_key"`
	RotatedAt    string `json:"rotated_at"`
	CrossSig     string `json:"old_key_signature"`
	NewKeySig    string `json:"new_key_signature"`
}

// RotationMessage is what both keys sign.
func RotationMessage(oldID, newID, newPub, at string) []byte {
	return []byte(fmt.Sprintf("ledger-key-rotation/v1\n%s\n%s\n%s\n%s", oldID, newID, newPub, at))
}

// Rotate generates a new active key. The old private key file is deleted unless keepOld;
// its public key stays so roots it signed keep verifying.
func (kr *Keyring) Rotate(keepOld bool) (Rotation, error) {
	old := kr.Active
	oldPub := old.Public().(ed25519.PublicKey)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Rotation{}, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	r := Rotation{
		OldKeyID: KeyID(oldPub), OldPublicKey: base64.StdEncoding.EncodeToString(oldPub),
		NewKeyID: KeyID(pub), NewPublicKey: base64.StdEncoding.EncodeToString(pub),
		RotatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	msg := RotationMessage(r.OldKeyID, r.NewKeyID, r.NewPublicKey, r.RotatedAt)
	r.CrossSig = base64.StdEncoding.EncodeToString(ed25519.Sign(old, msg))
	r.NewKeySig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
	if err := kr.install(priv); err != nil {
		return Rotation{}, err
	}
	if !keepOld {
		_ = os.Remove(filepath.Join(kr.Dir, fileID(r.OldKeyID)+".key"))
	}
	return r, nil
}

// VerifyRotation checks both signatures of a rotation statement.
func VerifyRotation(r Rotation) error {
	oldPub, err1 := base64.StdEncoding.DecodeString(r.OldPublicKey)
	newPub, err2 := base64.StdEncoding.DecodeString(r.NewPublicKey)
	cs, err3 := base64.StdEncoding.DecodeString(r.CrossSig)
	ns, err4 := base64.StdEncoding.DecodeString(r.NewKeySig)
	if err := errors.Join(err1, err2, err3, err4); err != nil || len(oldPub) != ed25519.PublicKeySize || len(newPub) != ed25519.PublicKeySize {
		return errors.New("rotation: malformed keys or signatures")
	}
	if KeyID(oldPub) != r.OldKeyID || KeyID(newPub) != r.NewKeyID {
		return errors.New("rotation: key id does not match public key")
	}
	msg := RotationMessage(r.OldKeyID, r.NewKeyID, r.NewPublicKey, r.RotatedAt)
	if !ed25519.Verify(oldPub, msg, cs) {
		return errors.New("rotation: old key signature invalid")
	}
	if !ed25519.Verify(newPub, msg, ns) {
		return errors.New("rotation: new key signature invalid")
	}
	return nil
}

// TrustSet is a set of trusted root-signing public keys by id. ECDSA keys (KMS/Vault) are
// stored under their "ecdsa-p256:" id with the PKIX DER bytes as value.
type TrustSet map[string]ed25519.PublicKey

// TrustFromRotations starts from the given trusted keys and adds every key introduced by a valid
// rotation whose old key is already trusted (rotations must be in order).
func TrustFromRotations(base TrustSet, rots []Rotation) (TrustSet, []error) {
	out := TrustSet{}
	for k, v := range base {
		out[k] = v
	}
	var errs []error
	for _, r := range rots {
		if err := VerifyRotation(r); err != nil {
			errs = append(errs, err)
			continue
		}
		if _, ok := out[r.OldKeyID]; !ok {
			errs = append(errs, fmt.Errorf("rotation to %s signed by untrusted key %s", r.NewKeyID, r.OldKeyID))
			continue
		}
		pub, _ := base64.StdEncoding.DecodeString(r.NewPublicKey)
		out[r.NewKeyID] = pub
	}
	return out, errs
}

// VerifyRootTrusted checks the signature and that the signing key is in trust.
func VerifyRootTrusted(r Root, trust TrustSet) error {
	if !VerifyRoot(r) {
		return errors.New("root signature invalid")
	}
	id := RootKeyID(r)
	if r.KeyID != "" && r.KeyID != id {
		return errors.New("root key_id does not match its public key")
	}
	if trust != nil {
		if _, ok := trust[id]; !ok {
			return fmt.Errorf("root signed by untrusted key %s", id)
		}
	}
	return nil
}

// MarshalRoot is the canonical JSON form of a root stored in receipts and anchor files.
func MarshalRoot(r Root) []byte {
	b, _ := json.MarshalIndent(r, "", "  ")
	return b
}

// LoadSigner resolves the signing key: LEDGER_KEYRING_DIR if set (initialised from the legacy
// key when empty), else the legacy single key (env or file). The keyring is nil in legacy mode.
func LoadSigner(envKey, keyFile, keyringDir string) (ed25519.PrivateKey, *Keyring, error) {
	if keyringDir == "" {
		k, err := LoadKey(envKey, keyFile)
		return k, nil, err
	}
	var seed ed25519.PrivateKey
	if _, err := os.Stat(filepath.Join(keyringDir, "active")); errors.Is(err, os.ErrNotExist) {
		if envKey != "" {
			k, err := LoadKey(envKey, "")
			if err != nil {
				return nil, nil, err
			}
			seed = k
		} else if _, err := os.Stat(keyFile); keyFile != "" && err == nil {
			k, err := LoadKey("", keyFile)
			if err != nil {
				return nil, nil, err
			}
			seed = k
		}
	}
	kr, err := OpenKeyring(keyringDir, seed)
	if err != nil {
		return nil, nil, err
	}
	return kr.Active, kr, nil
}
