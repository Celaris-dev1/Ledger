// Command ledger is the operator CLI: verify, replay, export, anchor.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/api"
	"github.com/Celaris-dev1/Ledger/internal/export"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

const usage = `ledger — tamper-evident agent decision log

usage:
  ledger verify [--chain NAME]           verify one chain (default: all chains); exit 1 if broken
  ledger replay --goal ID                print the ordered records for a goal as JSON
  ledger export --out DIR (--chain NAME ... | --goal ID)
                                         write pack.json + narrative.html (EU AI Act Art. 12/14)
  ledger anchor [--chain NAME] [--dir DIR]
                                         sign current chain root(s) with Ed25519 and write to DIR
  ledger project [--rebuild] [--check]   project new records into the domain tables (per-chain cursors);
                                         --rebuild starts from scratch; --check verifies rebuild == stored
  ledger incident --goal ID [--format json|html|md] [--out FILE]
                                         cross-product incident review for a goal (stdout by default)

env: LEDGER_DATABASE_URL, LEDGER_SIGNING_KEY (base64 seed) or LEDGER_KEY_FILE, LEDGER_ANCHOR_DIR
`

type multi []string

func (m *multi) String() string     { return fmt.Sprint(*m) }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "ledger: "+format+"\n", a...)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	var chains multi
	fs.Var(&chains, "chain", "chain name (repeatable)")
	goal := fs.String("goal", "", "goal id")
	out := fs.String("out", "auditor-pack", "output directory for export")
	dir := fs.String("dir", env("LEDGER_ANCHOR_DIR", "anchors"), "anchor output directory")
	rebuild := fs.Bool("rebuild", false, "project: rebuild from scratch")
	check := fs.Bool("check", false, "project: verify stored projection == rebuild")
	format := fs.String("format", "json", "incident: json|html|md")
	switch cmd {
	case "verify", "replay", "export", "anchor", "project", "incident":
		_ = fs.Parse(args)
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx := context.Background()
	st, err := store.Open(ctx, env("LEDGER_DATABASE_URL", "postgres://postgres:postgres@localhost:5432/ledger?sslmode=disable"))
	if err != nil {
		die("database: %v", err)
	}
	defer st.Close()
	if len(chains) == 0 && (cmd == "verify" || cmd == "anchor") {
		if chains, err = st.Chains(ctx); err != nil {
			die("%v", err)
		}
	}
	switch cmd {
	case "verify":
		broken := false
		for _, c := range chains {
			res, err := st.Verify(ctx, c)
			if err != nil {
				die("%v", err)
			}
			if res.OK {
				fmt.Printf("OK      %-20s length=%d head=%s\n", c, res.Length, res.Head)
			} else {
				broken = true
				fmt.Printf("BROKEN  %-20s length=%d broken_at=%d reason=%s\n", c, res.Length, *res.BrokenAt, res.Reason)
			}
		}
		if broken {
			st.Close()
			os.Exit(1)
		}
	case "replay":
		if *goal == "" {
			die("replay requires --goal")
		}
		recs, err := st.Replay(ctx, *goal)
		if err != nil {
			die("%v", err)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"goal_id": *goal, "records": recs})
	case "export":
		if len(chains) == 0 && *goal == "" {
			if chains, err = st.Chains(ctx); err != nil {
				die("%v", err)
			}
		}
		key, err := anchor.LoadKey(os.Getenv("LEDGER_SIGNING_KEY"), env("LEDGER_KEY_FILE", "ledger_ed25519.key"))
		if err != nil {
			die("signing key: %v", err)
		}
		p, err := api.BuildPack(ctx, st, key, chains, *goal)
		if err != nil {
			die("%v", err)
		}
		if err := os.MkdirAll(*out, 0o755); err != nil {
			die("%v", err)
		}
		jb, _ := json.MarshalIndent(p, "", "  ")
		if err := os.WriteFile(filepath.Join(*out, "pack.json"), jb, 0o644); err != nil {
			die("%v", err)
		}
		f, err := os.Create(filepath.Join(*out, "narrative.html"))
		if err != nil {
			die("%v", err)
		}
		if err := export.WriteHTML(f, p); err != nil {
			die("%v", err)
		}
		f.Close()
		fmt.Printf("wrote %s/pack.json and %s/narrative.html (%d records, intact=%v)\n", *out, *out, p.Summary.TotalRecords, p.Summary.AllChainsIntact)
	case "project":
		runProject(ctx, st, *rebuild, *check)
	case "incident":
		outFile := ""
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "out" {
				outFile = *out
			}
		})
		runIncident(ctx, st, *goal, *format, outFile)
	case "anchor":
		key, err := anchor.LoadKey(os.Getenv("LEDGER_SIGNING_KEY"), env("LEDGER_KEY_FILE", "ledger_ed25519.key"))
		if err != nil {
			die("signing key: %v", err)
		}
		for _, c := range chains {
			res, err := st.Verify(ctx, c)
			if err != nil {
				die("%v", err)
			}
			if !res.OK {
				die("refusing to anchor broken chain %s (broken_at=%d)", c, *res.BrokenAt)
			}
			root := anchor.Sign(key, c, int64(res.Length), res.Head)
			p, err := anchor.Write(*dir, root)
			if err != nil {
				die("%v", err)
			}
			if err := st.SaveAnchor(ctx, c, root.Seq, root.Head, root.Signature, root.PublicKey); err != nil {
				die("%v", err)
			}
			fmt.Printf("anchored %s seq=%d head=%s -> %s\n", c, root.Seq, root.Head, p)
		}
	}
}
