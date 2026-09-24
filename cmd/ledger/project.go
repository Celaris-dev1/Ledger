package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/incident"
	"github.com/Celaris-dev1/Ledger/internal/projection"
	"github.com/Celaris-dev1/Ledger/internal/receiptkeys"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

func runProject(ctx context.Context, st *store.Store, rebuild, check bool) {
	p := &projection.PG{Pool: st.Pool}
	var stats projection.Stats
	var err error
	if rebuild {
		stats, err = p.Rebuild(ctx)
	} else {
		stats, err = p.CatchUp(ctx)
	}
	if err != nil {
		die("project: %v", err)
	}
	b, _ := json.Marshal(stats)
	fmt.Printf("projected (version %d): %s\n", projection.Version, b)
	if check {
		diff, err := p.Check(ctx)
		if err != nil {
			die("check: %v", err)
		}
		if diff != "" {
			fmt.Printf("CHECK FAILED: stored projection differs from a rebuild:\n%s\n", diff)
			st.Close()
			os.Exit(1)
		}
		fmt.Println("check OK: stored projection == rebuild from records")
	}
}

func runIncident(ctx context.Context, st *store.Store, goal, format, outFile string, keyring *anchor.Keyring) {
	if goal == "" {
		die("incident requires --goal")
	}
	var opts []incident.Option
	// Default trust source: the enrolled receipt-key keyring (internal/receiptkeys). Enrolled
	// and unrevoked -> trusted:true; revoked before the receipt's issued_at -> rejected; unknown
	// -> trusted:false. Falls back to the local anchor keyring (LEDGER_KEYRING_DIR) for a key id
	// it doesn't recognize, so an operator's own root-signing key chain still verifies.
	rk := receiptkeys.Open(st.Pool)
	opts = append(opts, incident.WithTrust(func(keyID string, issuedAt time.Time) (string, []byte, bool) {
		if alg, pub, ok := rk.Trust(ctx, receiptkeys.DefaultTenant)(keyID, issuedAt); ok {
			return alg, pub, true
		}
		if keyring != nil {
			if pub, ok := keyring.Public[keyID]; ok {
				return "ed25519", []byte(pub), true
			}
		}
		return "", nil, false
	}))
	rep, err := incident.Build(ctx, st, goal, opts...)
	if err != nil {
		die("incident: %v", err)
	}
	if rep == nil {
		die("no records for goal %s", goal)
	}
	var w io.Writer = os.Stdout
	if outFile != "" {
		f, err := os.Create(outFile)
		if err != nil {
			die("%v", err)
		}
		defer f.Close()
		w = f
	}
	switch format {
	case "html":
		err = incident.WriteHTML(w, rep)
	case "md", "markdown":
		err = incident.WriteMarkdown(w, rep)
	case "json":
		err = incident.WriteJSON(w, rep)
	default:
		die("unknown --format %s (json|html|md)", format)
	}
	if err != nil {
		die("%v", err)
	}
	if outFile != "" {
		fmt.Fprintf(os.Stderr, "wrote %s: %s\n", outFile, rep.Summary.Headline)
	}
}
