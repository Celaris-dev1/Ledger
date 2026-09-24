package backup

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/anchoring"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// Loaded is a fully verified backup held in memory, ready to insert.
type Loaded struct {
	Manifest Manifest
	Chains   map[string][]store.Record
	Receipts []Receipt
	Anchors  []LegacyAnchor
	Keys     KeysMeta
	Warnings []string
}

// VerifyOptions controls restore verification.
type VerifyOptions struct {
	// Trust lists key ids allowed to have signed the manifest (keyring ids, rotations, KMS ids).
	// Empty: the signature must still verify, but against the key it names (a warning is emitted).
	Trust    anchor.TrustSet
	Verifier anchoring.Verifier // RFC 3161 trust bundle / git dir for receipt re-verification
}

// Load reads dir and verifies everything: manifest signature, file list and hashes, every
// chain's hash chain and head, and every anchor receipt against the backed-up records.
// Nothing is written anywhere.
func Load(dir string, opt VerifyOptions) (*Loaded, error) {
	mb, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(mb, &m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if m.Format != Format {
		return nil, fmt.Errorf("unsupported backup format %q", m.Format)
	}
	h, err := manifestHash(m)
	if err != nil {
		return nil, err
	}
	if h != m.ManifestHash {
		return nil, errors.New("manifest altered: its hash does not match")
	}
	if m.Signature == nil {
		return nil, errors.New("manifest is not signed")
	}
	if err := m.Signature.Verify([]byte(SignaturePrefix + h)); err != nil {
		return nil, fmt.Errorf("manifest signature: %w", err)
	}
	L := &Loaded{Manifest: m, Chains: map[string][]store.Record{}}
	if len(opt.Trust) > 0 {
		if _, ok := opt.Trust[m.Signature.KeyID]; !ok {
			return nil, fmt.Errorf("manifest signed by untrusted key %s", m.Signature.KeyID)
		}
	} else {
		L.Warnings = append(L.Warnings, "no trusted keys given: manifest signature checked against the key it names ("+m.Signature.KeyID+") only")
	}
	// every listed file hashes correctly; no unlisted files
	listed := map[string]FileEntry{}
	for _, f := range m.Files {
		if strings.Contains(f.Path, "..") || filepath.IsAbs(f.Path) {
			return nil, fmt.Errorf("bad path in manifest: %s", f.Path)
		}
		listed[f.Path] = f
		got, n, err := fileHash(filepath.Join(dir, f.Path))
		if err != nil {
			return nil, err
		}
		if got != f.SHA256 || n != f.Bytes {
			return nil, fmt.Errorf("file %s altered (sha256 %s, manifest %s)", f.Path, got, f.SHA256)
		}
	}
	err = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if _, ok := listed[rel]; !ok && rel != "manifest.json" {
			return fmt.Errorf("unlisted file in backup: %s", rel)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, need := range []string{"chains.json", "anchor_receipts.jsonl", "anchors.jsonl", "keys.json"} {
		if _, ok := listed[need]; !ok {
			return nil, fmt.Errorf("backup lacks %s", need)
		}
	}
	var heads []ChainHead
	if err := readJSON(filepath.Join(dir, "chains.json"), &heads); err != nil {
		return nil, err
	}
	if len(heads) != len(m.Chains) {
		return nil, errors.New("chains.json disagrees with the manifest")
	}
	var total int64
	for i, c := range m.Chains {
		if heads[i] != c {
			return nil, fmt.Errorf("chains.json disagrees with the manifest for %s", c.Name)
		}
		if _, ok := listed[c.File]; !ok {
			return nil, fmt.Errorf("chain file %s not listed", c.File)
		}
		var recs []store.Record
		if err := readJSONL(filepath.Join(dir, c.File), func(dec *json.Decoder) error {
			var r store.Record
			if err := dec.Decode(&r); err != nil {
				return err
			}
			if r.Chain != c.Name {
				return fmt.Errorf("record %s in %s belongs to chain %s", r.ID, c.File, r.Chain)
			}
			recs = append(recs, r)
			return nil
		}); err != nil {
			return nil, err
		}
		v := store.VerifyRecords(c.Name, recs)
		if !v.OK {
			return nil, fmt.Errorf("chain %s does not verify at seq %d: %s", c.Name, *v.BrokenAt, v.Reason)
		}
		if int64(v.Length) != c.HeadSeq || v.Head != c.Head {
			return nil, fmt.Errorf("chain %s: records end at seq %d head %s, manifest says %d %s (truncated?)", c.Name, v.Length, v.Head, c.HeadSeq, c.Head)
		}
		if store.TenantOfChain(c.Name) != c.Tenant {
			return nil, fmt.Errorf("chain %s: tenant %q does not match its name", c.Name, c.Tenant)
		}
		L.Chains[c.Name] = recs
		total += int64(len(recs))
	}
	if total != m.Records {
		return nil, fmt.Errorf("record count %d, manifest says %d", total, m.Records)
	}
	if err := readJSONL(filepath.Join(dir, "anchor_receipts.jsonl"), func(dec *json.Decoder) error {
		var r Receipt
		if err := dec.Decode(&r); err != nil {
			return err
		}
		L.Receipts = append(L.Receipts, r)
		return nil
	}); err != nil {
		return nil, err
	}
	if int64(len(L.Receipts)) != m.Receipts {
		return nil, errors.New("receipt count disagrees with the manifest")
	}
	byChain := map[string][]anchoring.StoredReceipt{}
	for _, r := range L.Receipts {
		byChain[r.Chain] = append(byChain[r.Chain], r.StoredReceipt)
	}
	for c, rs := range byChain {
		rep := anchoring.VerifyChain(c, L.Chains[c], rs, anchoring.Options{Verifier: opt.Verifier, Trust: opt.Trust})
		if !rep.OK {
			return nil, fmt.Errorf("anchor receipts of %s do not verify against the backed-up records: %s", c, strings.Join(rep.Findings, "; "))
		}
		for _, w := range rep.Warnings {
			if !strings.HasPrefix(w, "no keyring configured") {
				L.Warnings = append(L.Warnings, c+": "+w)
			}
		}
	}
	if err := readJSONL(filepath.Join(dir, "anchors.jsonl"), func(dec *json.Decoder) error {
		var a LegacyAnchor
		if err := dec.Decode(&a); err != nil {
			return err
		}
		if !anchor.VerifyRoot(anchor.Root{Chain: a.Chain, Seq: a.Seq, Head: a.Head, Signature: a.Signature, PublicKey: a.PublicKey}) {
			return fmt.Errorf("legacy signed root for %s seq %d does not verify", a.Chain, a.Seq)
		}
		L.Anchors = append(L.Anchors, a)
		return nil
	}); err != nil {
		return nil, err
	}
	if err := readJSON(filepath.Join(dir, "keys.json"), &L.Keys); err != nil {
		return nil, err
	}
	return L, nil
}

// ErrConflict is returned when the target already holds a chain from the backup.
var ErrConflict = errors.New("target database already contains chain")

// Restore verifies the backup (Load) and inserts it into st in one transaction, refusing to
// touch existing chains. It re-verifies every restored chain afterwards.
func Restore(ctx context.Context, st *store.Store, dir string, opt VerifyOptions) (*Loaded, error) {
	L, err := Load(dir, opt)
	if err != nil {
		return nil, fmt.Errorf("backup rejected: %w", err)
	}
	tx, err := st.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `LOCK TABLE chains IN EXCLUSIVE MODE`); err != nil {
		return nil, err
	}
	for _, c := range L.Manifest.Chains {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM chains WHERE name=$1) OR EXISTS(SELECT 1 FROM records WHERE chain=$1)`, c.Name).Scan(&exists); err != nil {
			return nil, err
		}
		if exists {
			return nil, fmt.Errorf("%w %s (restore only into an empty ledger or one without these chains)", ErrConflict, c.Name)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO chains(name, head_seq, head_hash) VALUES ($1,$2,$3)`, c.Name, c.HeadSeq, c.Head); err != nil {
			return nil, err
		}
		for _, r := range L.Chains[c.Name] {
			if _, err := tx.Exec(ctx, `INSERT INTO records(id,chain,seq,type,goal_id,actor_chain,policy_version,payload,created_at,prev_hash,hash,idempotency_key)
				VALUES ($1,$2,$3,$4,NULLIF($5,''),$6,NULLIF($7,''),$8,$9,$10,$11,NULLIF($12,''))`,
				r.ID, r.Chain, r.Seq, r.Type, r.GoalID, string(r.ActorChain), r.PolicyVersion, string(r.Payload), r.CreatedAt, r.PrevHash, r.Hash, r.IdempotencyKey); err != nil {
				return nil, fmt.Errorf("insert %s/%d: %w", r.Chain, r.Seq, err)
			}
		}
	}
	for _, r := range L.Receipts {
		m := r.Meta
		if len(m) == 0 {
			m = json.RawMessage(`{}`)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO anchor_receipts (chain, seq, head, root_digest, key_id, root_json, backend, kind, receipt, meta, anchored_at, verified_at, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, r.Chain, r.Seq, r.Head, r.RootDigest, r.KeyID, r.RootJSON, r.Backend, r.Kind,
			r.StoredReceipt.Receipt, string(m), r.AnchoredAt, r.VerifiedAt, r.CreatedAt); err != nil {
			return nil, err
		}
	}
	for _, a := range L.Anchors {
		if _, err := tx.Exec(ctx, `INSERT INTO anchors(chain,seq,head,signature,public_key,anchored_at) VALUES ($1,$2,$3,$4,$5,$6)`,
			a.Chain, a.Seq, a.Head, a.Signature, a.PublicKey, a.AnchoredAt); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	for _, c := range L.Manifest.Chains {
		v, err := st.Verify(ctx, c.Name)
		if err != nil {
			return L, err
		}
		if !v.OK || v.Head != c.Head {
			return L, fmt.Errorf("restored chain %s failed post-restore verification: %s", c.Name, v.Reason)
		}
	}
	return L, nil
}

func fileHash(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, err
}

func readJSON(p string, v any) error {
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func readJSONL(p string, each func(*json.Decoder) error) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(bufio.NewReaderSize(f, 1<<20))
	for dec.More() {
		if err := each(dec); err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(p), err)
		}
	}
	return nil
}
