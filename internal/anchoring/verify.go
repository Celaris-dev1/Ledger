package anchoring

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

// StoredReceipt is a row of anchor_receipts (or an external root file, ID 0).
type StoredReceipt struct {
	ID         int64           `json:"id"`
	Chain      string          `json:"chain"`
	Seq        int64           `json:"seq"`
	Head       string          `json:"head"`
	RootDigest string          `json:"root_digest"`
	KeyID      string          `json:"key_id"`
	RootJSON   string          `json:"root_json"`
	Backend    string          `json:"backend"`
	Kind       string          `json:"kind"`
	Receipt    []byte          `json:"receipt"`
	Meta       json.RawMessage `json:"meta"`
	AnchoredAt time.Time       `json:"anchored_at"`
	VerifiedAt time.Time       `json:"verified_at"`
}

// Check statuses.
const (
	StatusOK           = "ok"           // receipt valid and its head is on the current chain
	StatusRewritten    = "rewritten"    // receipt valid but the current chain no longer has this head
	StatusInvalid      = "invalid"      // receipt/root fails verification (tampered receipt row?)
	StatusUnverifiable = "unverifiable" // cannot check with this configuration (e.g. no trust bundle)
)

// AnchorCheck is the verdict for one receipt.
type AnchorCheck struct {
	ID          int64     `json:"id,omitempty"`
	Seq         int64     `json:"seq"`
	Head        string    `json:"head"`
	Backend     string    `json:"backend"`
	Kind        string    `json:"kind"`
	KeyID       string    `json:"key_id,omitempty"`
	AnchoredAt  time.Time `json:"anchored_at"`
	Status      string    `json:"status"`
	Valid       bool      `json:"receipt_valid"` // the receipt itself verified (independent of the chain)
	Detail      string    `json:"detail,omitempty"`
	CurrentHash string    `json:"current_hash,omitempty"`
}

// ChainReport is the result of verifying one chain against its anchors.
type ChainReport struct {
	Chain        string        `json:"chain"`
	Length       int           `json:"length"`
	Head         string        `json:"head"`
	ChainIntact  bool          `json:"chain_intact"` // plain hash-chain verification
	OK           bool          `json:"ok"`           // intact AND every anchor valid and consistent
	Rewritten    bool          `json:"rewritten"`
	LastAnchored int64         `json:"last_anchored_seq"`
	Checks       []AnchorCheck `json:"anchors"`
	Findings     []string      `json:"findings,omitempty"`
	Warnings     []string      `json:"warnings,omitempty"`
}

// Options for VerifyChain.
type Options struct {
	Verifier Verifier
	Trust    anchor.TrustSet // nil = accept any validly self-signed root (warned)
	Quorum   int             // required valid RFC 3161 tokens per anchored seq (0 = don't check)
}

// VerifyChain re-verifies every receipt offline and proves each anchored (seq, head) is a prefix of recs.
func VerifyChain(chain string, recs []store.Record, receipts []StoredReceipt, opt Options) ChainReport {
	vr := store.VerifyRecords(chain, recs)
	rep := ChainReport{Chain: chain, Length: len(recs), Head: vr.Head, ChainIntact: vr.OK, OK: vr.OK}
	if !vr.OK {
		rep.Findings = append(rep.Findings, fmt.Sprintf("hash chain broken at seq %d: %s", *vr.BrokenAt, vr.Reason))
	}
	if opt.Trust == nil {
		rep.Warnings = append(rep.Warnings, "no keyring configured: root signatures checked against their embedded keys only")
	}
	tsaOK := map[int64]int{}
	for _, sr := range receipts {
		c := checkReceipt(sr, recs, opt)
		if c.Valid && sr.Kind == KindRFC3161 {
			tsaOK[sr.Seq]++
		}
		if c.Status == StatusOK && sr.Seq > rep.LastAnchored {
			rep.LastAnchored = sr.Seq
		}
		rep.Checks = append(rep.Checks, c)
	}
	sort.SliceStable(rep.Checks, func(i, j int) bool { return rep.Checks[i].Seq < rep.Checks[j].Seq })

	// Summarise rewrites: the earliest anchored seq whose head changed, and the latest anchor before it that still matches.
	var firstBad int64 = -1
	var lastGood int64
	for _, c := range rep.Checks {
		switch c.Status {
		case StatusRewritten:
			rep.Rewritten, rep.OK = true, false
			if firstBad < 0 || c.Seq < firstBad {
				firstBad = c.Seq
			}
		case StatusInvalid:
			rep.OK = false
			rep.Findings = append(rep.Findings, fmt.Sprintf("receipt %d (%s, seq %d) invalid: %s", c.ID, c.Backend, c.Seq, c.Detail))
		case StatusUnverifiable:
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("receipt %d (%s, seq %d) unverifiable: %s", c.ID, c.Backend, c.Seq, c.Detail))
		}
	}
	if firstBad >= 0 {
		for _, c := range rep.Checks {
			if c.Status == StatusOK && c.Seq < firstBad && c.Seq > lastGood {
				lastGood = c.Seq
			}
		}
		rep.Findings = append([]string{fmt.Sprintf(
			"HISTORY REWRITTEN: the chain no longer contains head(s) that were externally anchored; "+
				"records in seq range (%d, %d] were altered or removed after being anchored", lastGood, firstBad)}, rep.Findings...)
		bySeq := map[int64][]string{}
		var seqs []int64
		cur := map[int64]string{}
		heads := map[int64]string{}
		for _, c := range rep.Checks {
			if c.Status == StatusRewritten {
				if _, ok := bySeq[c.Seq]; !ok {
					seqs = append(seqs, c.Seq)
				}
				tag := c.Backend
				if strings.HasPrefix(tag, "dir:") {
					tag = "dir"
				}
				if !c.Valid {
					tag += "(receipt unverified)"
				}
				bySeq[c.Seq] = append(bySeq[c.Seq], tag)
				cur[c.Seq], heads[c.Seq] = c.Detail, c.Head
			}
		}
		for _, sq := range seqs {
			rep.Findings = append(rep.Findings, fmt.Sprintf("  seq %d: anchored head %s witnessed by [%s]; %s",
				sq, heads[sq], strings.Join(bySeq[sq], ", "), cur[sq]))
		}
	}
	if opt.Quorum > 0 {
		seen := map[int64]bool{}
		for _, sr := range receipts {
			if sr.Kind == KindRFC3161 && !seen[sr.Seq] {
				seen[sr.Seq] = true
				if tsaOK[sr.Seq] < opt.Quorum {
					rep.Warnings = append(rep.Warnings, fmt.Sprintf("seq %d: %d valid RFC 3161 token(s), quorum is %d", sr.Seq, tsaOK[sr.Seq], opt.Quorum))
				}
			}
		}
	}
	if len(receipts) == 0 {
		rep.Warnings = append(rep.Warnings, "no anchors recorded for this chain")
	}
	return rep
}

func checkReceipt(sr StoredReceipt, recs []store.Record, opt Options) AnchorCheck {
	c := AnchorCheck{ID: sr.ID, Seq: sr.Seq, Head: sr.Head, Backend: sr.Backend, Kind: sr.Kind, KeyID: sr.KeyID, AnchoredAt: sr.AnchoredAt}
	bad := func(status, f string, a ...any) AnchorCheck { c.Status, c.Detail = status, fmt.Sprintf(f, a...); return c }
	var root anchor.Root
	if err := json.Unmarshal([]byte(sr.RootJSON), &root); err != nil {
		return bad(StatusInvalid, "stored root is not JSON")
	}
	if root.Chain != sr.Chain || root.Seq != sr.Seq || root.Head != sr.Head {
		return bad(StatusInvalid, "row (seq/head) disagrees with the signed root it carries")
	}
	if err := anchor.VerifyRootTrusted(root, opt.Trust); err != nil {
		return bad(StatusInvalid, "%v", err)
	}
	subj := NewSubject(root)
	if sr.RootDigest != "" && sr.RootDigest != hex.EncodeToString(subj.Digest) {
		return bad(StatusInvalid, "root_digest column does not match the root")
	}
	at, err := opt.Verifier.VerifyReceipt(Receipt{Backend: sr.Backend, Kind: sr.Kind, Bytes: sr.Receipt, Meta: sr.Meta, AnchoredAt: sr.AnchoredAt}, subj)
	if errors.Is(err, ErrUnverifiable) {
		c.Status, c.Detail = StatusUnverifiable, err.Error()
		// fall through to the prefix check: the signed root alone still binds (seq, head)
	} else if err != nil {
		return bad(StatusInvalid, "%v", err)
	} else {
		c.AnchoredAt = at
		c.Status, c.Valid = StatusOK, true
	}
	if sr.Seq < 1 || sr.Seq > int64(len(recs)) {
		c.Status, c.Detail = StatusRewritten, fmt.Sprintf("chain now has only %d records (truncated)", len(recs))
		return c
	}
	cur := recs[sr.Seq-1]
	if cur.Seq != sr.Seq || cur.Hash != sr.Head {
		c.CurrentHash = cur.Hash
		c.Status, c.Detail = StatusRewritten, "current record hash is "+cur.Hash
	}
	return c
}

// ScanRootDir loads anchored roots from an anchor directory (layout of anchor.Write:
// DIR/<chain>/<seq>.json) as external receipts for one chain. They carry no third-party
// timestamp but are signed by the root key, which a DB admin does not hold.
func ScanRootDir(dir, chain string) ([]StoredReceipt, error) {
	safe := strings.Map(func(c rune) rune {
		if c == '/' || c == '\\' || c == '.' {
			return '_'
		}
		return c
	}, chain)
	d := filepath.Join(dir, safe)
	ents, err := os.ReadDir(d)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []StoredReceipt
	for _, e := range ents {
		if e.IsDir() || e.Name() == "latest.json" || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		p := filepath.Join(d, e.Name())
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var r anchor.Root
		if err := json.Unmarshal(b, &r); err != nil || r.Chain != chain {
			continue
		}
		fi, _ := e.Info()
		out = append(out, StoredReceipt{Chain: r.Chain, Seq: r.Seq, Head: r.Head, KeyID: r.KeyID, RootJSON: string(b),
			Backend: "dir:" + p, Kind: KindFile, Receipt: b, Meta: meta(map[string]string{"path": p}), AnchoredAt: fi.ModTime().UTC()})
	}
	return out, nil
}

// FormatReport renders a human-readable report.
func FormatReport(r ChainReport) string {
	var b strings.Builder
	state := "OK     "
	switch {
	case r.Rewritten:
		state = "REWRITTEN"
	case !r.OK:
		state = "FAILED "
	}
	counts := map[string]int{}
	for _, c := range r.Checks {
		counts[c.Status]++
	}
	fmt.Fprintf(&b, "%s %-20s length=%d head=%s anchors=%d (ok=%d rewritten=%d invalid=%d unverifiable=%d) last_anchored_seq=%d\n",
		state, r.Chain, r.Length, r.Head, len(r.Checks), counts[StatusOK], counts[StatusRewritten], counts[StatusInvalid], counts[StatusUnverifiable], r.LastAnchored)
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "  ! %s\n", f)
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "  ~ %s\n", w)
	}
	return b.String()
}
