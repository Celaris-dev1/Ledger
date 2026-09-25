// Package bundle builds and reads offline verifier bundles: self-contained tar archives holding
// a chain's records, its signed roots, external anchor receipts (including RFC 3161 timestamp
// tokens), and the public keys needed to check all of it — everything cmd/ledger-verify needs
// with no database and no network access.
//
// A bundle proves nothing by itself beyond what internal/anchoring.VerifyChain already proves
// online: the hash chain is intact, root signatures check out, and every anchor receipt still
// matches the chain. Bundling just packages that evidence so a third party (an auditor, a
// counterparty, a court) can re-run the same checks without ever touching Ledger's database.
package bundle

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Celaris-dev1/Ledger/internal/anchoring"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

// Format is the bundle format identifier, bumped on incompatible layout changes.
const Format = "ledger-bundle/v1"

// Manifest is bundle/manifest.json.
type Manifest struct {
	Format    string   `json:"format"`
	CreatedAt string   `json:"created_at"` // RFC3339
	GoalID    string   `json:"goal_id,omitempty"`
	Chains    []string `json:"chains"`
	// TrustMode explains how root signatures were checked: "keyring" (an operator-controlled
	// trust set was embedded) or "self-signed" (each root was only checked against its own
	// embedded public key — anyone who could edit the database could also mint that key).
	TrustMode string `json:"trust_mode"`
	Note      string `json:"note,omitempty"`
}

// Chain is one chain's evidence inside a bundle.
type Chain struct {
	Records  []store.Record
	Receipts []anchoring.StoredReceipt
}

// Bundle is the full in-memory contents of a bundle.tar.
type Bundle struct {
	Manifest Manifest
	Chains   map[string]Chain // chain name -> evidence
	// Trust maps a root/rotation key id to its base64-encoded public key bytes. It is used only
	// to check membership (which key ids are trusted); the raw bytes are not otherwise used, so
	// the same map serves Ed25519 and ECDSA key ids alike.
	Trust map[string]string
	// TSARoots is a PEM bundle of RFC 3161 TSA certificates, if any tokens are present.
	TSARoots []byte
}

const (
	pathManifest = "manifest.json"
	pathTrust    = "trust.json"
	pathTSARoots = "tsa_roots.pem"
)

func recordsPath(chain string) string { return "chains/" + chain + "/records.json" }
func anchorsPath(chain string) string { return "chains/" + chain + "/anchors.json" }

// Write serialises b as a gzip-compressed tar stream.
func Write(w io.Writer, b Bundle) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)

	add := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(data)), Mode: 0o644}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}

	mb, err := json.MarshalIndent(b.Manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := add(pathManifest, mb); err != nil {
		return err
	}

	if len(b.Trust) > 0 {
		tb, err := json.MarshalIndent(b.Trust, "", "  ")
		if err != nil {
			return err
		}
		if err := add(pathTrust, tb); err != nil {
			return err
		}
	}
	if len(b.TSARoots) > 0 {
		if err := add(pathTSARoots, b.TSARoots); err != nil {
			return err
		}
	}

	names := make([]string, 0, len(b.Chains))
	for c := range b.Chains {
		names = append(names, c)
	}
	sort.Strings(names)
	for _, c := range names {
		ch := b.Chains[c]
		rb, err := json.MarshalIndent(ch.Records, "", "  ")
		if err != nil {
			return err
		}
		if err := add(recordsPath(c), rb); err != nil {
			return err
		}
		ab, err := json.MarshalIndent(ch.Receipts, "", "  ")
		if err != nil {
			return err
		}
		if err := add(anchorsPath(c), ab); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// maxEntrySize bounds any single file inside a bundle we will decompress into memory. Bundles are
// audit archives of a bounded chain, not a place for a hostile-input decompression bomb.
const maxEntrySize = 1 << 30 // 1 GiB

// Read parses a bundle produced by Write. It tolerates a plain (non-gzip) tar too, so bundles
// can be repacked by hand without breaking cmd/ledger-verify.
func Read(r io.Reader) (Bundle, error) {
	var b Bundle
	b.Chains = map[string]Chain{}

	br := bufio.NewReader(r)
	var tr *tar.Reader
	if peek, err := br.Peek(2); err == nil && len(peek) == 2 && peek[0] == 0x1f && peek[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return b, fmt.Errorf("bundle: gzip: %w", err)
		}
		defer gz.Close()
		tr = tar.NewReader(gz)
	} else {
		tr = tar.NewReader(br)
	}

	records := map[string][]byte{}
	receipts := map[string][]byte{}
	haveManifest := false

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return b, fmt.Errorf("bundle: corrupt tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// Tolerate a "./" prefix, which GNU tar adds when archiving a directory with `-C dir .`
		// (as a hand-repacked bundle typically is): the layout is otherwise unaffected.
		name := strings.TrimPrefix(hdr.Name, "./")
		if hdr.Size < 0 || hdr.Size > maxEntrySize {
			return b, fmt.Errorf("bundle: %s: implausible size %d", hdr.Name, hdr.Size)
		}
		data := make([]byte, hdr.Size)
		if _, err := io.ReadFull(tr, data); err != nil {
			return b, fmt.Errorf("bundle: %s: %w", hdr.Name, err)
		}
		switch {
		case name == pathManifest:
			if err := json.Unmarshal(data, &b.Manifest); err != nil {
				return b, fmt.Errorf("bundle: manifest.json: %w", err)
			}
			haveManifest = true
		case name == pathTrust:
			if err := json.Unmarshal(data, &b.Trust); err != nil {
				return b, fmt.Errorf("bundle: trust.json: %w", err)
			}
		case name == pathTSARoots:
			b.TSARoots = data
		case strings.HasPrefix(name, "chains/") && strings.HasSuffix(name, "/records.json"):
			chain := strings.TrimSuffix(strings.TrimPrefix(name, "chains/"), "/records.json")
			if chain != "" && !strings.Contains(chain, "/") {
				records[chain] = data
			}
		case strings.HasPrefix(name, "chains/") && strings.HasSuffix(name, "/anchors.json"):
			chain := strings.TrimSuffix(strings.TrimPrefix(name, "chains/"), "/anchors.json")
			if chain != "" && !strings.Contains(chain, "/") {
				receipts[chain] = data
			}
		}
	}
	if !haveManifest {
		return b, fmt.Errorf("bundle: missing %s", pathManifest)
	}
	if b.Manifest.Format != Format {
		return b, fmt.Errorf("bundle: unsupported format %q (want %q)", b.Manifest.Format, Format)
	}
	for _, name := range b.Manifest.Chains {
		var ch Chain
		rb, ok := records[name]
		if !ok {
			return b, fmt.Errorf("bundle: manifest lists chain %q but %s is missing", name, recordsPath(name))
		}
		if err := json.Unmarshal(rb, &ch.Records); err != nil {
			return b, fmt.Errorf("bundle: %s: %w", recordsPath(name), err)
		}
		if ab, ok := receipts[name]; ok {
			if err := json.Unmarshal(ab, &ch.Receipts); err != nil {
				return b, fmt.Errorf("bundle: %s: %w", anchorsPath(name), err)
			}
		}
		b.Chains[name] = ch
	}
	return b, nil
}
