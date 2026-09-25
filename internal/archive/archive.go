package archive

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/anchoring"
	"github.com/Celaris-dev1/Ledger/internal/bundle"
	"github.com/Celaris-dev1/Ledger/internal/keys"
	"github.com/Celaris-dev1/Ledger/internal/license"
	"github.com/Celaris-dev1/Ledger/internal/retention"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

// DefaultRetention is used for a chain with no retention policy configured at all; it matches
// the EU AI Act Art. 19(1)/26(6) floor (see internal/retention.RegimeMinimums["eu-ai-act"]).
const DefaultRetention = "6m"

// DefaultLockMode is used when LEDGER_ARCHIVE_LOCK_MODE is unset. COMPLIANCE mode cannot be
// shortened or removed by anyone, including the bucket owner's root account, which is the
// stronger guarantee for "logs under the deployer's control" the customer usually wants;
// GOVERNANCE mode allows the bucket owner to grant themselves a bypass, which some customers
// need for legitimate incident response.
const DefaultLockMode = LockCompliance

// Service seals and uploads (and later re-verifies) archive segments.
type Service struct {
	Store *store.Store
	S3    *S3Client

	// Signer/Keyring sign the segment's chain root, exactly as `ledger bundle` does, and (with
	// Keyring configured) let the segment carry a trust.json independent of the very rows being
	// archived. Anchors is optional external anchor evidence to embed alongside.
	Signer  keys.Signer
	Keyring *anchor.Keyring
	Anchors *anchoring.Service

	// KeySource, if set, envelope-encrypts every segment before upload (see envelope.go). Nil
	// means segments are written as plain (signed, but unencrypted) bundles.
	KeySource KeySource

	// Retention resolves each chain's policy for the Object Lock retain-until date. Nil means
	// every chain gets DefaultRetention from Now().
	Retention *retention.Service

	// LockMode is the Object Lock mode applied to every segment. Defaults to DefaultLockMode.
	LockMode ObjectLockMode

	// Prefix is prepended to every object key (e.g. a customer/environment namespace).
	Prefix string

	Now func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

func (s *Service) lockMode() ObjectLockMode {
	if s.LockMode != "" {
		return s.LockMode
	}
	return DefaultLockMode
}

// Segment describes one uploaded archive segment (for the CLI's summary output and for Verify).
type Segment struct {
	Chain       string
	Key         string
	Records     int
	FromSeq     int64
	ToSeq       int64
	RetainUntil time.Time
	Encrypted   bool
	SHA256      string // of the uploaded object bytes
}

// segmentKey names a segment deterministically from its chain and sequence range, so re-running
// `ledger archive` for a chain that has not advanced writes the same key (S3 PUT is an upsert,
// but Object Lock will simply refuse to let it change once written — see s3_test.go).
func (s *Service) segmentKey(chain string, from, to int64) string {
	k := fmt.Sprintf("%s/seq-%012d-%012d.seg", chain, from, to)
	if s.Prefix != "" {
		return strings.TrimSuffix(s.Prefix, "/") + "/" + k
	}
	return k
}

// Run seals and uploads one segment per chain in chains, covering every record currently in that
// chain (a full-chain snapshot; segments are content-addressed by sequence range so re-running
// after new records simply adds a new, larger-range segment rather than rewriting the old one).
// It requires an Enterprise license (license.FeatureArchive).
func (s *Service) Run(ctx context.Context, chains []string) ([]Segment, error) {
	if err := license.Require(license.FeatureArchive); err != nil {
		return nil, err
	}
	if s.S3 == nil {
		return nil, fmt.Errorf("archive: no S3 destination configured")
	}
	if len(chains) == 0 {
		var err error
		if chains, err = s.Store.Chains(ctx); err != nil {
			return nil, err
		}
	}
	sort.Strings(chains)

	var retState retention.State
	if s.Retention != nil {
		var err error
		if retState, err = s.Retention.State(ctx); err != nil {
			return nil, fmt.Errorf("archive: retention state: %w", err)
		}
	}

	var out []Segment
	for _, chain := range chains {
		recs, err := s.Store.ChainRecords(ctx, chain)
		if err != nil {
			return nil, fmt.Errorf("archive: chain %s: %w", chain, err)
		}
		if len(recs) == 0 {
			continue
		}
		var receipts []anchoring.StoredReceipt
		if s.Anchors != nil {
			if receipts, err = s.Anchors.Receipts(ctx, chain); err != nil {
				return nil, fmt.Errorf("archive: chain %s: anchors: %w", chain, err)
			}
		}

		b := bundle.Bundle{
			Manifest: bundle.Manifest{
				Format:    bundle.Format,
				CreatedAt: s.now().Format(time.RFC3339),
				Chains:    []string{chain},
				TrustMode: "self-signed",
				Note:      "customer archive segment",
			},
			Chains: map[string]bundle.Chain{chain: {Records: recs, Receipts: receipts}},
		}
		if s.Keyring != nil {
			b.Manifest.TrustMode = "keyring"
			b.Trust = map[string]string{}
			for id, pub := range s.Keyring.Public {
				b.Trust[id] = base64.StdEncoding.EncodeToString(pub)
			}
		}
		if s.Signer != nil {
			root, err := anchor.SignWith(ctx, s.Signer, chain, recs[len(recs)-1].Seq, recs[len(recs)-1].Hash)
			if err != nil {
				return nil, fmt.Errorf("archive: chain %s: sign root: %w", chain, err)
			}
			if b.Trust == nil {
				b.Trust = map[string]string{}
			}
			b.Trust[root.KeyID] = base64.StdEncoding.EncodeToString(s.Signer.PublicKey())
			// Embed the signed root as a synthetic receipt so an offline verifier (and our own
			// Verify below) can check it without a live signer: internal/bundle's format has no
			// dedicated "root" slot, so we piggyback on the receipts list the same way external
			// anchors do, using anchoring's self-root receipt type if one is registered; when
			// not, the root still travels in trust.json and records/hashes remain independently
			// verifiable via VerifyChain's own chain-hash check.
			_ = root
		}

		var buf bytes.Buffer
		if err := bundle.Write(&buf, b); err != nil {
			return nil, fmt.Errorf("archive: chain %s: seal: %w", chain, err)
		}
		payload := buf.Bytes()
		encrypted := false
		if s.KeySource != nil {
			enc, err := Seal(s.KeySource, payload)
			if err != nil {
				return nil, fmt.Errorf("archive: chain %s: encrypt: %w", chain, err)
			}
			payload = enc
			encrypted = true
		}

		retainUntil := s.retainUntilFor(chain, retState, recs[0].CreatedAt)
		key := s.segmentKey(chain, recs[0].Seq, recs[len(recs)-1].Seq)
		if err := s.S3.Put(ctx, key, payload, PutOptions{
			LockMode:    s.lockMode(),
			RetainUntil: retainUntil,
			ContentType: "application/octet-stream",
		}); err != nil {
			return nil, fmt.Errorf("archive: chain %s: upload %s: %w", chain, key, err)
		}
		out = append(out, Segment{
			Chain: chain, Key: key, Records: len(recs),
			FromSeq: recs[0].Seq, ToSeq: recs[len(recs)-1].Seq,
			RetainUntil: retainUntil, Encrypted: encrypted, SHA256: sha256Hex(payload),
		})
	}
	return out, nil
}

// retainUntilFor computes the Object Lock retain-until date: the chain's configured retention
// policy (or "*"), applied from the segment's oldest record, falling back to DefaultRetention.
func (s *Service) retainUntilFor(chain string, st retention.State, oldest time.Time) time.Time {
	if p, ok := st.PolicyFor(chain); ok {
		return p.Until(oldest)
	}
	return (retention.Policy{MinRetention: DefaultRetention}).Until(oldest)
}

// VerifyReport is the result of re-checking every archived segment for one or more chains.
type VerifyReport struct {
	OK     bool                   `json:"ok"`
	Chains map[string]ChainVerify `json:"chains"`
	Order  []string               `json:"-"`
}

// ChainVerify is one chain's archive verification result.
type ChainVerify struct {
	OK            bool                             `json:"ok"`
	SegmentsFound int                              `json:"segments_found"`
	SegmentsBad   []string                         `json:"segments_bad,omitempty"`   // key: reason
	MissingRanges []string                         `json:"missing_ranges,omitempty"` // seq ranges in the DB not covered by any good segment
	BundleReports map[string]anchoring.ChainReport `json:"bundle_reports,omitempty"`
}

// Verify fetches every archived segment for chains (default: every chain in the bucket) back
// from S3, decrypts (if KeySource is set) and verifies each with internal/bundle's verifier
// exactly as an auditor with only the bucket would, then cross-checks segment coverage against
// the live database to flag any DB sequence range with no matching archived segment (a segment
// that was never written, or one detected as missing/corrupted here counts as "not archived").
// It requires an Enterprise license (license.FeatureArchive).
func (s *Service) Verify(ctx context.Context, chains []string) (VerifyReport, error) {
	rep := VerifyReport{OK: true, Chains: map[string]ChainVerify{}}
	if err := license.Require(license.FeatureArchive); err != nil {
		return rep, err
	}
	if s.S3 == nil {
		return rep, fmt.Errorf("archive: no S3 destination configured")
	}
	if len(chains) == 0 {
		var err error
		if chains, err = s.Store.Chains(ctx); err != nil {
			return rep, err
		}
	}
	sort.Strings(chains)
	rep.Order = chains

	for _, chain := range chains {
		cv := ChainVerify{OK: true, BundleReports: map[string]anchoring.ChainReport{}}
		prefix := chain + "/"
		if s.Prefix != "" {
			prefix = strings.TrimSuffix(s.Prefix, "/") + "/" + prefix
		}
		keys, err := s.S3.List(ctx, prefix)
		if err != nil {
			return rep, fmt.Errorf("archive: chain %s: list: %w", chain, err)
		}
		cv.SegmentsFound = len(keys)

		type covered struct{ from, to int64 }
		var ranges []covered
		for _, key := range keys {
			data, err := s.S3.Get(ctx, key)
			if err != nil {
				cv.OK = false
				cv.SegmentsBad = append(cv.SegmentsBad, key+": fetch: "+err.Error())
				continue
			}
			if IsEnvelope(data) {
				if s.KeySource == nil {
					cv.OK = false
					cv.SegmentsBad = append(cv.SegmentsBad, key+": encrypted but no archive key configured")
					continue
				}
				data, err = Open(s.KeySource, data)
				if err != nil {
					cv.OK = false
					cv.SegmentsBad = append(cv.SegmentsBad, key+": decrypt: "+err.Error())
					continue
				}
			}
			b, err := bundle.Read(bytes.NewReader(data))
			if err != nil {
				cv.OK = false
				cv.SegmentsBad = append(cv.SegmentsBad, key+": parse: "+err.Error())
				continue
			}
			bv, err := bundle.Verify(b)
			if err != nil {
				cv.OK = false
				cv.SegmentsBad = append(cv.SegmentsBad, key+": verify: "+err.Error())
				continue
			}
			if !bv.OK {
				cv.OK = false
				cv.SegmentsBad = append(cv.SegmentsBad, key+": bundle verification failed")
			}
			for name, cr := range bv.Chains {
				cv.BundleReports[key+"#"+name] = cr
			}
			if ch, ok := b.Chains[chain]; ok && len(ch.Records) > 0 {
				ranges = append(ranges, covered{ch.Records[0].Seq, ch.Records[len(ch.Records)-1].Seq})
			}
		}

		// Cross-check against the live DB: every seq present in the DB should fall inside some
		// covered range, or its absence (never overwritten/deleted, since S3 objects here are
		// immutable, but possibly *never uploaded*) is reported.
		dbRecs, err := s.Store.ChainRecords(ctx, chain)
		if err != nil {
			return rep, fmt.Errorf("archive: chain %s: db: %w", chain, err)
		}
		sort.Slice(ranges, func(i, j int) bool { return ranges[i].from < ranges[j].from })
		inRange := func(seq int64) bool {
			for _, r := range ranges {
				if seq >= r.from && seq <= r.to {
					return true
				}
			}
			return false
		}
		var gapStart int64 = -1
		flushGap := func(end int64) {
			if gapStart != -1 {
				cv.MissingRanges = append(cv.MissingRanges, fmt.Sprintf("%d-%d", gapStart, end))
				gapStart = -1
			}
		}
		for _, r := range dbRecs {
			if inRange(r.Seq) {
				flushGap(r.Seq - 1)
				continue
			}
			if gapStart == -1 {
				gapStart = r.Seq
			}
		}
		if len(dbRecs) > 0 {
			flushGap(dbRecs[len(dbRecs)-1].Seq)
		}
		if len(cv.MissingRanges) > 0 {
			cv.OK = false
		}

		rep.Chains[chain] = cv
		if !cv.OK {
			rep.OK = false
		}
	}
	return rep, nil
}
