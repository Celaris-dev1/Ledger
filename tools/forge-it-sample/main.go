// Command forge-it-sample builds the deterministic sample bundle published at docs/forge-it/
// for the "Forge It" public challenge (see docs/forge-it.md). It needs no database and no
// network: it builds a small in-memory chain, signs its root with a fresh Ed25519 key that it
// then discards (only the public key, embedded in the root, ships in the bundle), and writes an
// offline-verifiable bundle.tar plus a plain-text description of the chain it built.
//
// Run via scripts/forge-it-sample.sh (`go run ./tools/forge-it-sample`).
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/anchoring"
	"github.com/Celaris-dev1/Ledger/internal/bundle"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

// fixedSeed makes the sample byte-for-byte reproducible across runs (fixed key material,
// fixed timestamps): a challenge sample must be the same file every time it's regenerated, or
// "reproduce the sample" would itself be ambiguous.
const fixedSeed = 42

// epoch is the fixed "created_at" for every record, so the bundle never changes with wall time.
var epoch = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

const chainName = "forge-it-sample"

func main() {
	outDir := "docs/forge-it"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		die(err)
	}

	rng := rand.New(rand.NewSource(fixedSeed))
	priv := deterministicKey(rng)

	recs := buildChain()
	root := anchor.Sign(priv, chainName, int64(len(recs)), recs[len(recs)-1].Hash)
	// Force a fixed SignedAt so the bundle is byte-identical across regenerations; the field is
	// not part of the signed message (see anchor.Message), so this does not touch the signature.
	root.SignedAt = epoch.Add(time.Hour).Format(time.RFC3339)

	subj := anchoring.NewSubject(root)
	fileReceipt := anchoring.StoredReceipt{
		ID: 1, Chain: chainName, Seq: root.Seq, Head: root.Head, RootDigest: subj.DigestHex(),
		KeyID: root.KeyID, RootJSON: string(subj.RootJSON), Backend: anchoring.KindFile, Kind: anchoring.KindFile,
		Receipt: subj.RootJSON, Meta: json.RawMessage(`{"path":"sample"}`),
		AnchoredAt: epoch.Add(time.Hour), VerifiedAt: epoch.Add(time.Hour),
	}

	b := bundle.Bundle{
		Manifest: bundle.Manifest{
			Format: bundle.Format, CreatedAt: epoch.Format(time.RFC3339), Chains: []string{chainName},
			TrustMode: "self-signed",
			Note: "Forge It sample: the signing key was generated and discarded at build time (see " +
				"tools/forge-it-sample); only the public key, embedded in the signed root below, ships here.",
		},
		Chains: map[string]bundle.Chain{
			chainName: {Records: recs, Receipts: []anchoring.StoredReceipt{fileReceipt}},
		},
	}

	tarPath := filepath.Join(outDir, "sample-bundle.tar")
	f, err := os.Create(tarPath)
	if err != nil {
		die(err)
	}
	if err := bundle.Write(f, b); err != nil {
		die(err)
	}
	if err := f.Close(); err != nil {
		die(err)
	}

	// Sanity-check the sample verifies clean before publishing it — a broken "forge it" sample
	// would be a poor start to a challenge about verification.
	rep, err := bundle.Verify(b)
	if err != nil {
		die(err)
	}
	if !rep.OK {
		die(fmt.Errorf("sample bundle does not verify clean: %+v", rep))
	}

	readme := filepath.Join(outDir, "README.txt")
	if err := os.WriteFile(readme, []byte(sampleReadme(root)), 0o644); err != nil {
		die(err)
	}
	fmt.Printf("wrote %s and %s (chain=%q, %d records, root seq=%d head=%s)\n",
		tarPath, readme, chainName, len(recs), root.Seq, root.Head)
}

func sampleReadme(root anchor.Root) string {
	return fmt.Sprintf(`This is the sample bundle for the Ledger "Forge It" challenge (see docs/forge-it.md).

It was generated deterministically by tools/forge-it-sample (run via scripts/forge-it-sample.sh)
and contains no private key material: the Ed25519 signing key was generated in memory, used once
to sign the chain root below, and discarded. Only its public key (embedded in the root) ships.

  chain:      %s
  root seq:   %d
  root head:  %s
  key id:     %s
  public key: %s

Verify it with:

  go run ./cmd/ledger-verify docs/forge-it/sample-bundle.tar

Then try to beat it: edit sample-bundle.tar (modify a record, reorder, delete, insert, truncate,
swap the root signature or the anchor receipt) and see if ledger-verify still says OK. See
docs/forge-it.md for the rules and what's out of scope.
`, root.Chain, root.Seq, root.Head, root.KeyID, root.PublicKey)
}

func buildChain() []store.Record {
	type step struct {
		typ     string
		payload string
	}
	steps := []step{
		{"goal.created", `{"goal":"ship the Q3 pricing page","owner":"agent-7"}`},
		{"plan.proposed", `{"steps":["draft copy","review with legal","publish"]}`},
		{"tool.called", `{"tool":"cms.publish_draft","args":{"page":"pricing"}}`},
		{"human.approved", `{"approver":"jordan@example.com","note":"looks good"}`},
		{"goal.completed", `{"result":"published","url":"https://example.com/pricing"}`},
	}
	var recs []store.Record
	prev := ""
	for i, st := range steps {
		r := store.Record{
			Chain: chainName, Seq: int64(i + 1), Type: st.typ,
			ActorChain: json.RawMessage(`[{"kind":"agent","id":"agent-7"}]`),
			Payload:    json.RawMessage(st.payload),
			CreatedAt:  epoch.Add(time.Duration(i) * time.Minute),
			PrevHash:   prev,
		}
		h, err := store.ComputeHash(&r)
		if err != nil {
			die(err)
		}
		r.Hash = h
		prev = h
		recs = append(recs, r)
	}
	return recs
}

// deterministicKey derives a fixed Ed25519 key from rng so the sample is reproducible without
// committing any key material: the seed lives only in this generator's source, not in the bundle.
func deterministicKey(rng *rand.Rand) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	_, _ = rng.Read(seed)
	return ed25519.NewKeyFromSeed(seed)
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "forge-it-sample: "+err.Error())
	os.Exit(1)
}
