package keys

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ErrKeyDestroyed is returned for a subject whose data key was shredded.
var ErrKeyDestroyed = errors.New("data key destroyed (crypto-shredded)")

// ErrNoKey is returned when a subject has no data key.
var ErrNoKey = errors.New("no data key for subject")

// DataKeyStore holds one AES-256 data key per data subject. Destroy must make the key
// unrecoverable from this store and leave a tombstone so later lookups report ErrKeyDestroyed
// (and GetOrCreate never silently re-creates a shredded subject's key).
type DataKeyStore interface {
	// GetOrCreate returns the subject's key and its key id, creating it on first use.
	GetOrCreate(subject string) (keyID string, key []byte, err error)
	// Get returns the key for keyID (ErrKeyDestroyed / ErrNoKey).
	Get(keyID string) ([]byte, error)
	// Destroy shreds the subject's key. Idempotent.
	Destroy(subject string) (keyID string, err error)
	// KeyIDFor is the (deterministic) key id of a subject; no key material involved.
	KeyIDFor(subject string) string
}

// FileDataKeyStore keeps keys as files in Dir (0600):
//
//	<keyid>.key        base64 AES-256 key
//	<keyid>.destroyed  tombstone (key file overwritten with zeros, then removed)
//
// Key ids are "dk:"+hex(sha256("ledger-subject/v1\n"+subject)[:12]) so the subject identifier
// itself is not stored in file names or in records.
type FileDataKeyStore struct {
	Dir string
	mu  sync.Mutex
}

func (f *FileDataKeyStore) KeyIDFor(subject string) string {
	h := sha256.Sum256([]byte("ledger-subject/v1\n" + subject))
	return "dk:" + hex.EncodeToString(h[:12])
}

func (f *FileDataKeyStore) path(id, ext string) string {
	return filepath.Join(f.Dir, strings.ReplaceAll(id, ":", "_")+ext)
}

func (f *FileDataKeyStore) GetOrCreate(subject string) (string, []byte, error) {
	if subject == "" {
		return "", nil, errors.New("empty data subject")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	id := f.KeyIDFor(subject)
	k, err := f.get(id)
	if err == nil || !errors.Is(err, ErrNoKey) {
		return id, k, err
	}
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return "", nil, err
	}
	k = make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return "", nil, err
	}
	tmp := f.path(id, ".tmp")
	if err := os.WriteFile(tmp, []byte(base64.StdEncoding.EncodeToString(k)), 0o600); err != nil {
		return "", nil, err
	}
	return id, k, os.Rename(tmp, f.path(id, ".key"))
}

func (f *FileDataKeyStore) Get(id string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.get(id)
}

func (f *FileDataKeyStore) get(id string) ([]byte, error) {
	if _, err := os.Stat(f.path(id, ".destroyed")); err == nil {
		return nil, ErrKeyDestroyed
	}
	b, err := os.ReadFile(f.path(id, ".key"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoKey
	}
	if err != nil {
		return nil, err
	}
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(k) != 32 {
		return nil, fmt.Errorf("data key %s is corrupt", id)
	}
	return k, nil
}

func (f *FileDataKeyStore) Destroy(subject string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := f.KeyIDFor(subject)
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return id, err
	}
	// tombstone first, so a crash never leaves a re-creatable subject
	if err := os.WriteFile(f.path(id, ".destroyed"), []byte("destroyed\n"), 0o600); err != nil {
		return id, err
	}
	p := f.path(id, ".key")
	if st, err := os.Stat(p); err == nil {
		// best-effort overwrite before unlink (filesystems may keep old blocks; the key is
		// also never written anywhere else by Ledger)
		_ = os.WriteFile(p, make([]byte, st.Size()), 0o600)
		if err := os.Remove(p); err != nil {
			return id, err
		}
	}
	return id, nil
}
