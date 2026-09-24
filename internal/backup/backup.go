// Package backup writes and restores consistent, signed logical backups of a Ledger database
// without pg_dump.
//
// Layout of a backup directory:
//
//	manifest.json              format, snapshot time, chain heads, sha256+size of every file, signature
//	chains.json                [{name, tenant, head_seq, head_hash}]
//	chains/<n>-<name>.jsonl    every record of the chain in seq order (exact stored fields)
//	anchor_receipts.jsonl      external anchor receipts (append-only table)
//	anchors.jsonl              legacy signed roots (ledger anchor)
//	keys.json                  public key metadata only (keyring ids + public keys, signer id); never private keys
//
// Everything is read in one REPEATABLE READ, READ ONLY transaction (a consistent snapshot).
// The manifest is signed with the ledger root key (any keys.Signer). Restore verifies the
// signature, every file hash, every chain's hash chain and every anchor receipt against the
// restored records *before* inserting anything, then inserts in one transaction and
// re-verifies. Derived data (projections, domain tables) is not backed up: rebuild it with
// `ledger project --rebuild`.
package backup

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/anchoring"
	"github.com/Celaris-dev1/Ledger/internal/canon"
	"github.com/Celaris-dev1/Ledger/internal/keys"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

// Format identifies the backup layout.
const Format = "ledger-backup/v1"

// SignaturePrefix is prepended to the manifest hash before signing.
const SignaturePrefix = "ledger-backup-manifest/v1\n"

// FileEntry lists one file of the backup.
type FileEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// ChainHead is a chain's head at snapshot time.
type ChainHead struct {
	Name    string `json:"name"`
	Tenant  string `json:"tenant"`
	HeadSeq int64  `json:"head_seq"`
	Head    string `json:"head_hash"`
	File    string `json:"file"`
}

// Manifest is manifest.json.
type Manifest struct {
	Format       string          `json:"format"`
	CreatedAt    string          `json:"created_at"`
	Chains       []ChainHead     `json:"chains"`
	Records      int64           `json:"records"`
	Receipts     int64           `json:"anchor_receipts"`
	Files        []FileEntry     `json:"files"`
	ManifestHash string          `json:"manifest_hash,omitempty"`
	Signature    *keys.Signature `json:"signature,omitempty"`
}

// KeysMeta is keys.json.
type KeysMeta struct {
	SignerKeyID string            `json:"signer_key_id"`
	SignerAlg   string            `json:"signer_alg"`
	SignerPub   string            `json:"signer_public_key"`
	Keyring     map[string]string `json:"keyring_public_keys,omitempty"` // id -> base64 public key
	ActiveKeyID string            `json:"keyring_active_key_id,omitempty"`
}

// Receipt row as exported.
type Receipt struct {
	anchoring.StoredReceipt
	CreatedAt time.Time `json:"created_at"`
}

// LegacyAnchor is a row of the anchors table.
type LegacyAnchor struct {
	Chain      string    `json:"chain"`
	Seq        int64     `json:"seq"`
	Head       string    `json:"head"`
	Signature  string    `json:"signature"`
	PublicKey  string    `json:"public_key"`
	AnchoredAt time.Time `json:"anchored_at"`
}

func manifestHash(m Manifest) (string, error) {
	m.ManifestHash, m.Signature = "", nil
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	c, err := canon.CanonicalBytes(b)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(c)
	return hex.EncodeToString(h[:]), nil
}

func chainFile(i int, name string) string {
	safe := strings.Map(func(c rune) rune {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			return c
		}
		return '_'
	}, name)
	if len(safe) > 60 {
		safe = safe[:60]
	}
	return fmt.Sprintf("chains/%05d-%s.jsonl", i, safe)
}

func encoder(w io.Writer) *json.Encoder {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false) // keep payload text byte-identical
	return enc
}

// Options for Create.
type Options struct {
	Signer  keys.Signer
	Keyring *anchor.Keyring // optional: public keys recorded in keys.json
	Now     func() time.Time
}

// Create writes a backup of every chain into dir (which must not exist or be empty).
func Create(ctx context.Context, st *store.Store, dir string, opt Options) (Manifest, error) {
	if opt.Signer == nil {
		return Manifest{}, errors.New("backup: a signer is required")
	}
	if ents, err := os.ReadDir(dir); err == nil && len(ents) > 0 {
		return Manifest{}, fmt.Errorf("backup: %s is not empty", dir)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Manifest{}, err
	}
	now := time.Now().UTC()
	if opt.Now != nil {
		now = opt.Now()
	}
	tx, err := st.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return Manifest{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	m := Manifest{Format: Format, CreatedAt: now.Format(time.RFC3339Nano)}
	var files []FileEntry
	add := func(rel string, write func(enc *json.Encoder) error) error {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		h := sha256.New()
		cw := &countWriter{w: io.MultiWriter(f, h)}
		bw := bufio.NewWriterSize(cw, 1<<20)
		if err := write(encoder(bw)); err != nil {
			f.Close()
			return err
		}
		if err := bw.Flush(); err != nil {
			f.Close()
			return err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		files = append(files, FileEntry{Path: rel, SHA256: hex.EncodeToString(h.Sum(nil)), Bytes: cw.n})
		return nil
	}

	rows, err := tx.Query(ctx, `SELECT name, tenant, head_seq, head_hash FROM chains ORDER BY name`)
	if err != nil {
		return m, err
	}
	for rows.Next() {
		var c ChainHead
		if err := rows.Scan(&c.Name, &c.Tenant, &c.HeadSeq, &c.Head); err != nil {
			rows.Close()
			return m, err
		}
		m.Chains = append(m.Chains, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return m, err
	}
	for i := range m.Chains {
		c := &m.Chains[i]
		c.File = chainFile(i, c.Name)
		err := add(c.File, func(enc *json.Encoder) error {
			var after int64
			for {
				rs, err := tx.Query(ctx, `SELECT id::text, chain, seq, type, COALESCE(goal_id,''), actor_chain::text, COALESCE(policy_version,''),
					payload::text, created_at, prev_hash, hash, COALESCE(idempotency_key,'') FROM records WHERE chain=$1 AND seq>$2 ORDER BY seq LIMIT 5000`, c.Name, after)
				if err != nil {
					return err
				}
				n := 0
				for rs.Next() {
					var r store.Record
					var ac, pl string
					if err := rs.Scan(&r.ID, &r.Chain, &r.Seq, &r.Type, &r.GoalID, &ac, &r.PolicyVersion, &pl, &r.CreatedAt, &r.PrevHash, &r.Hash, &r.IdempotencyKey); err != nil {
						rs.Close()
						return err
					}
					r.CreatedAt = r.CreatedAt.UTC()
					r.ActorChain, r.Payload = json.RawMessage(ac), json.RawMessage(pl)
					if err := enc.Encode(r); err != nil {
						rs.Close()
						return err
					}
					after, n = r.Seq, n+1
					m.Records++
				}
				rs.Close()
				if err := rs.Err(); err != nil {
					return err
				}
				if n < 5000 {
					return nil
				}
			}
		})
		if err != nil {
			return m, err
		}
	}
	if err := add("chains.json", func(enc *json.Encoder) error { return enc.Encode(m.Chains) }); err != nil {
		return m, err
	}
	if err := add("anchor_receipts.jsonl", func(enc *json.Encoder) error {
		rs, err := tx.Query(ctx, `SELECT id, chain, seq, head, root_digest, key_id, root_json, backend, kind, receipt, meta::text,
			anchored_at, verified_at, created_at FROM anchor_receipts ORDER BY id`)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var r Receipt
			var meta string
			if err := rs.Scan(&r.ID, &r.Chain, &r.Seq, &r.Head, &r.RootDigest, &r.KeyID, &r.RootJSON, &r.Backend, &r.Kind, &r.StoredReceipt.Receipt, &meta,
				&r.AnchoredAt, &r.VerifiedAt, &r.CreatedAt); err != nil {
				return err
			}
			r.Meta = json.RawMessage(meta)
			r.AnchoredAt, r.VerifiedAt, r.CreatedAt = r.AnchoredAt.UTC(), r.VerifiedAt.UTC(), r.CreatedAt.UTC()
			if err := enc.Encode(r); err != nil {
				return err
			}
			m.Receipts++
		}
		return rs.Err()
	}); err != nil {
		return m, err
	}
	if err := add("anchors.jsonl", func(enc *json.Encoder) error {
		rs, err := tx.Query(ctx, `SELECT chain, seq, head, signature, public_key, anchored_at FROM anchors ORDER BY id`)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var a LegacyAnchor
			if err := rs.Scan(&a.Chain, &a.Seq, &a.Head, &a.Signature, &a.PublicKey, &a.AnchoredAt); err != nil {
				return err
			}
			a.AnchoredAt = a.AnchoredAt.UTC()
			if err := enc.Encode(a); err != nil {
				return err
			}
		}
		return rs.Err()
	}); err != nil {
		return m, err
	}
	km := KeysMeta{SignerKeyID: opt.Signer.KeyID(), SignerAlg: opt.Signer.Algorithm(), SignerPub: b64(opt.Signer.PublicKey())}
	if opt.Keyring != nil {
		km.Keyring, km.ActiveKeyID = map[string]string{}, opt.Keyring.ActiveID()
		for id, pub := range opt.Keyring.Public {
			km.Keyring[id] = b64(pub)
		}
	}
	if err := add("keys.json", func(enc *json.Encoder) error { return enc.Encode(km) }); err != nil {
		return m, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	m.Files = files
	if m.Chains == nil {
		m.Chains = []ChainHead{}
	}
	if m.ManifestHash, err = manifestHash(m); err != nil {
		return m, err
	}
	sig, err := keys.SignDetached(ctx, opt.Signer, []byte(SignaturePrefix+m.ManifestHash))
	if err != nil {
		return m, err
	}
	m.Signature = &sig
	mb, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), mb, 0o644); err != nil {
		return m, err
	}
	return m, tx.Commit(ctx)
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
