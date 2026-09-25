// Command ledger-verify is a standalone offline verifier for `ledger bundle` archives. It opens
// no database connection and makes no network call: it only reads the bundle file and reports
// whether the hash chain, root signatures, anchor receipts and RFC 3161 timestamp tokens it
// carries are all internally consistent.
//
// Exit code is 0 only if every chain in the bundle verified clean; otherwise 1, with the first
// failing record/chain named in the output.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Celaris-dev1/Ledger/internal/anchoring"
	"github.com/Celaris-dev1/Ledger/internal/bundle"
)

const usage = `ledger-verify — offline verifier for ledger bundle archives (no DB, no network)

usage:
  ledger-verify [--json] FILE

exit status:
  0   every chain in the bundle verified (hash chain intact, root signatures and anchors valid)
  1   the bundle is malformed, or at least one chain failed verification
`

func main() {
	asJSON := flag.Bool("json", false, "print a JSON report instead of text")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	path := flag.Arg(0)

	f, err := os.Open(path)
	if err != nil {
		fail(*asJSON, fmt.Sprintf("cannot open bundle: %v", err))
	}
	defer f.Close()

	b, err := bundle.Read(f)
	if err != nil {
		fail(*asJSON, fmt.Sprintf("cannot read bundle: %v", err))
	}

	rep, err := bundle.Verify(b)
	if err != nil {
		fail(*asJSON, fmt.Sprintf("cannot verify bundle: %v", err))
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	} else {
		fmt.Printf("bundle: %s\n", path)
		fmt.Printf("format:  %s\n", b.Manifest.Format)
		fmt.Printf("created: %s\n", b.Manifest.CreatedAt)
		if b.Manifest.GoalID != "" {
			fmt.Printf("goal:    %s\n", b.Manifest.GoalID)
		}
		fmt.Printf("trust:   %s\n", b.Manifest.TrustMode)
		if b.Manifest.Note != "" {
			fmt.Printf("note:    %s\n", b.Manifest.Note)
		}
		fmt.Println()
		for _, name := range rep.Order {
			fmt.Print(anchoring.FormatReport(rep.Chains[name]))
		}
	}

	if !rep.OK {
		os.Exit(1)
	}
}

func fail(asJSON bool, msg string) {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		_ = enc.Encode(map[string]any{"ok": false, "error": msg})
	} else {
		fmt.Fprintln(os.Stderr, "ledger-verify: "+msg)
	}
	os.Exit(1)
}
