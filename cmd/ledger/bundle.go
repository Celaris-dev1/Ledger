package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/anchoring"
	"github.com/Celaris-dev1/Ledger/internal/bundle"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

const bundleUsage = `  ledger bundle (--chain NAME [--chain NAME...] | --goal ID) --out FILE
                                         write a self-contained, offline-verifiable bundle: chain
                                         records, signed roots, external anchor receipts (RFC 3161
                                         tokens included), and the public keys needed to check them.
                                         Check it with the standalone ledger-verify binary — no
                                         database, no network, no Ledger account required.
`

// runBundle implements `ledger bundle`.
func runBundle(args []string) {
	fs := flag.NewFlagSet("bundle", flag.ExitOnError)
	var chains multi
	fs.Var(&chains, "chain", "chain name (repeatable)")
	goal := fs.String("goal", "", "bundle every chain touched by this goal id")
	out := fs.String("out", "bundle.tar", "output path")
	_ = fs.Parse(args)

	if len(chains) == 0 && *goal == "" {
		die("bundle requires --chain or --goal")
	}

	ctx := context.Background()
	st, err := store.Open(ctx, env("LEDGER_DATABASE_URL", "postgres://postgres:postgres@localhost:5432/ledger?sslmode=disable"))
	if err != nil {
		die("bundle: database: %v", err)
	}
	defer st.Close()

	names := []string(chains)
	if *goal != "" {
		recs, err := st.Replay(ctx, *goal)
		if err != nil {
			die("bundle: replay goal %s: %v", *goal, err)
		}
		if len(recs) == 0 {
			die("bundle: goal %s has no records", *goal)
		}
		seen := map[string]bool{}
		for _, r := range recs {
			if !seen[r.Chain] {
				seen[r.Chain] = true
				names = append(names, r.Chain)
			}
		}
	}

	acfg, err := anchoring.ConfigFromEnv(os.Getenv)
	if err != nil {
		die("bundle: anchoring config: %v", err)
	}
	// A keyring, if configured, is what makes root-signature trust independent of the very
	// database rows being bundled; without it the bundle is honestly labelled self-signed.
	var keyring *anchor.Keyring
	if os.Getenv("LEDGER_KEYRING_DIR") != "" {
		if _, kr, err := anchor.LoadSigner(os.Getenv("LEDGER_SIGNING_KEY"), env("LEDGER_KEY_FILE", "ledger_ed25519.key"), os.Getenv("LEDGER_KEYRING_DIR")); err == nil {
			keyring = kr
		}
	}
	svc := acfg.Service(st, nil, keyring, nil)

	b := bundle.Bundle{
		Manifest: bundle.Manifest{
			Format:    bundle.Format,
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
			GoalID:    *goal,
			Chains:    names,
			TrustMode: "self-signed",
		},
		Chains: map[string]bundle.Chain{},
	}

	trust, warnings, err := svc.Trust(ctx)
	if err != nil {
		die("bundle: trust: %v", err)
	}
	if trust != nil {
		b.Manifest.TrustMode = "keyring"
		b.Trust = map[string]string{}
		for id, pub := range trust {
			b.Trust[id] = base64.StdEncoding.EncodeToString(pub)
		}
	}
	for _, w := range warnings {
		b.Manifest.Note += w + "; "
	}

	if svc.Verifier.TSARoots != nil {
		if p := os.Getenv("LEDGER_TSA_TRUST"); p != "" {
			if pem, err := os.ReadFile(p); err == nil {
				b.TSARoots = pem
			}
		}
	}

	for _, chain := range names {
		recs, err := st.ChainRecords(ctx, chain)
		if err != nil {
			die("bundle: chain %s: %v", chain, err)
		}
		if len(recs) == 0 {
			die("bundle: chain %s has no records", chain)
		}
		receipts, err := svc.Receipts(ctx, chain)
		if err != nil {
			die("bundle: chain %s: anchors: %v", chain, err)
		}
		for _, d := range svc.RootDirs {
			ext, err := anchoring.ScanRootDir(d, chain)
			if err != nil {
				die("bundle: chain %s: root dir %s: %v", chain, d, err)
			}
			receipts = append(receipts, ext...)
		}
		// external roots embed the raw signed root, not a copy of the anchor_receipts row's
		// Receipt bytes needed on disk if trust is self-signed but the receipt bytes are
		// otherwise identical to what checkReceipt reads.
		b.Chains[chain] = bundle.Chain{Records: recs, Receipts: receipts}
	}

	f, err := os.Create(*out)
	if err != nil {
		die("bundle: %v", err)
	}
	defer f.Close()
	if err := bundle.Write(f, b); err != nil {
		die("bundle: write: %v", err)
	}
	fmt.Printf("bundle: wrote %s (%d chain(s), trust=%s)\n", *out, len(names), b.Manifest.TrustMode)
}
