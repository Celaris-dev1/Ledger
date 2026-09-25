package main

// Customer-owned S3 archive sink (EU AI Act Art. 19/26 "logs under the deployer's control"):
// `ledger archive` seals current chain records into the same bundle format as `ledger bundle`
// and writes them to the customer's own S3-compatible bucket under Object Lock; `ledger archive
// verify` fetches them back and checks them, cross-referenced against the live database.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Celaris-dev1/Ledger/internal/anchoring"
	"github.com/Celaris-dev1/Ledger/internal/archive"
	"github.com/Celaris-dev1/Ledger/internal/license"
	"github.com/Celaris-dev1/Ledger/internal/retention"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

const archiveUsage = `  ledger archive [--chain NAME ...]      seal current chain records (same format as ` + "`ledger bundle`" + `)
                                         and write them to the customer's S3-compatible bucket
                                         under Object Lock (Enterprise: LEDGER_LICENSE)
  ledger archive verify [--chain NAME ...] [--json]
                                         fetch archived segments back, verify them, and flag any
                                         database sequence range with no matching good segment

env: LEDGER_ARCHIVE_S3_ENDPOINT, _BUCKET, _REGION, _ACCESS_KEY_ID, _SECRET_ACCESS_KEY (secrets from
     env only), _PATH_STYLE=1 (MinIO), LEDGER_ARCHIVE_KEY_FILE (customer AES-256 key: encrypts every
     segment; omit to write plain signed bundles), LEDGER_ARCHIVE_LOCK_MODE=COMPLIANCE|GOVERNANCE,
     LEDGER_ARCHIVE_PREFIX
`

func archiveService(ctx context.Context, st *store.Store) *archive.Service {
	cfg, ok, err := archive.S3ConfigFromEnv(os.Getenv)
	if err != nil {
		die("archive: %v", err)
	}
	if !ok {
		die("archive: not configured; set LEDGER_ARCHIVE_S3_ENDPOINT/_BUCKET/_REGION/_ACCESS_KEY_ID/_SECRET_ACCESS_KEY")
	}
	svc := &archive.Service{
		Store:     st,
		S3:        &archive.S3Client{Cfg: cfg},
		Retention: &retention.Service{Store: st},
		Prefix:    os.Getenv("LEDGER_ARCHIVE_PREFIX"),
	}
	switch strings.ToUpper(os.Getenv("LEDGER_ARCHIVE_LOCK_MODE")) {
	case "GOVERNANCE":
		svc.LockMode = archive.LockGovernance
	case "", "COMPLIANCE":
		svc.LockMode = archive.LockCompliance
	default:
		die("archive: LEDGER_ARCHIVE_LOCK_MODE must be COMPLIANCE or GOVERNANCE")
	}
	if lk, has, err := archive.LocalKeyFileFromEnv(os.Getenv); err != nil {
		die("archive: %v", err)
	} else if has {
		svc.KeySource = lk
	}
	sg, kr := signer(ctx)
	svc.Signer, svc.Keyring = sg, kr
	acfg, err := anchoring.ConfigFromEnv(os.Getenv)
	if err != nil {
		die("archive: anchoring config: %v", err)
	}
	svc.Anchors = acfg.Service(st, anchorKey(sg), kr, nil)
	return svc
}
func runArchive(args []string) {
	if err := license.Require(license.FeatureArchive); err != nil {
		die("%v", err)
	}
	ctx := context.Background()
	if len(args) > 0 && args[0] == "verify" {
		runArchiveVerify(ctx, args[1:])
		return
	}
	fs := flag.NewFlagSet("archive", flag.ExitOnError)
	var chains multi
	fs.Var(&chains, "chain", "chain name (repeatable; default: every chain)")
	_ = fs.Parse(args)

	st := openStore(ctx)
	defer st.Close()
	svc := archiveService(ctx, st)
	segs, err := svc.Run(ctx, chains)
	if err != nil {
		die("archive: %v", err)
	}
	if len(segs) == 0 {
		fmt.Println("archive: nothing to do (no records in scope)")
		return
	}
	for _, s := range segs {
		enc := ""
		if s.Encrypted {
			enc = " encrypted"
		}
		fmt.Printf("archive: %s -> %s (%d records, seq %d-%d, retain-until %s%s)\n",
			s.Chain, s.Key, s.Records, s.FromSeq, s.ToSeq, s.RetainUntil.Format("2006-01-02"), enc)
	}
}

func runArchiveVerify(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("archive verify", flag.ExitOnError)
	var chains multi
	fs.Var(&chains, "chain", "chain name (repeatable; default: every chain)")
	asJSON := fs.Bool("json", false, "JSON output")
	_ = fs.Parse(args)

	st := openStore(ctx)
	defer st.Close()
	svc := archiveService(ctx, st)
	rep, err := svc.Verify(ctx, chains)
	if err != nil {
		die("archive: %v", err)
	}
	if *asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(rep)
	} else {
		for _, name := range rep.Order {
			cv := rep.Chains[name]
			status := "OK"
			if !cv.OK {
				status = "FAIL"
			}
			fmt.Printf("%s  %s  %d segment(s) found\n", status, name, cv.SegmentsFound)
			for _, bad := range cv.SegmentsBad {
				fmt.Printf("  bad segment: %s\n", bad)
			}
			for _, m := range cv.MissingRanges {
				fmt.Printf("  missing from archive: seq %s\n", m)
			}
		}
	}
	if !rep.OK {
		os.Exit(1)
	}
}
