// Command ledger is the operator CLI: verify, replay, export, anchor.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/anchoring"
	"github.com/Celaris-dev1/Ledger/internal/api"
	"github.com/Celaris-dev1/Ledger/internal/export"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

const usage = `ledger — tamper-evident agent decision log

usage:
  ledger verify [--chain NAME]           verify one chain (default: all chains); exit 1 if broken
  ledger verify --anchors [--chain NAME] [--json]
                                         also re-verify every external anchor receipt offline and prove
                                         each anchored head is still on the chain (detects rehashed history)
  ledger replay --goal ID                print the ordered records for a goal as JSON
  ledger export --out DIR (--chain NAME ... | --goal ID)
                                         write pack.json + narrative.html (EU AI Act Art. 12/14)
  ledger anchor [--chain NAME] [--dir DIR]
                                         sign current chain root(s) with Ed25519 and write to DIR
  ledger anchor --external [--chain NAME] [--dir DIR]
                                         anchor now via the configured backends (TSAs, git, dir) and store receipts
  ledger keys list | rotate [--keep-old] [--operator ID]
                                         show / rotate the root-signing keyring (LEDGER_KEYRING_DIR);
                                         a rotation is recorded in the "ledger" system chain;
                                         list also prints the enrolled stack-receipt trust keyring
                                         (optionally filtered with --product), even without LEDGER_KEYRING_DIR
  ledger keys enroll --product P --key-id ID --public-key <base64|@file> [--alg ed25519|ecdsa-p256-sha256]
                                         enroll a product's receipt-signing public key so
                                         incident/verify-receipt report it trusted
  ledger keys revoke --key-id ID --reason R
                                         revoke an enrolled receipt-signer key; receipts it signed
                                         before the revocation stay trusted, later ones don't
  ledger project [--rebuild] [--check]   project new records into the domain tables (per-chain cursors);
                                         --rebuild starts from scratch; --check verifies rebuild == stored
  ledger incident --goal ID [--format json|html|md] [--out FILE]
                                         cross-product incident review for a goal (stdout by default)
  ledger token create --name NAME [--role writer|viewer|auditor|admin] | list | revoke ID
                                         manage API tokens (stored hashed; plaintext printed once)
  ledger license show [--json] | verify <token|file>
                                         current/verify an Enterprise license (see LICENSING in README)
` + bundleUsage + verifyReceiptUsage + `

env: LEDGER_DATABASE_URL, LEDGER_SIGNING_KEY (base64 seed) or LEDGER_KEY_FILE, LEDGER_KEYRING_DIR,
     LEDGER_ANCHOR_DIR, LEDGER_TSA_URLS, LEDGER_TSA_TRUST, LEDGER_TSA_QUORUM, LEDGER_ANCHOR_GIT_REMOTE,
     LEDGER_ANCHOR_GIT_DIR, LEDGER_ANCHOR_GIT_BRANCH (see README "External anchoring")
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
	if cmd == "verify-receipt" {
		runVerifyReceipt(args)
		return
	}
	if cmd == "bundle" {
		runBundle(args)
		return
	}
	if cmd == "license" {
		if err := cmdLicense(args); err != nil {
			die("%v", err)
		}
		return
	}
	if runOps(cmd, args) {
		return
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	var chains multi
	fs.Var(&chains, "chain", "chain name (repeatable)")
	goal := fs.String("goal", "", "goal id")
	out := fs.String("out", "auditor-pack", "output directory for export")
	dir := fs.String("dir", env("LEDGER_ANCHOR_DIR", "anchors"), "anchor output directory")
	withAnchors := fs.Bool("anchors", false, "verify: also check external anchor receipts")
	asJSON := fs.Bool("json", false, "verify --anchors: print JSON reports")
	external := fs.Bool("external", false, "anchor: use the configured external backends")
	keepOld := fs.Bool("keep-old", false, "keys rotate: keep the retired private key on disk")
	operator := fs.String("operator", env("USER", "operator"), "keys rotate: human operator id recorded in the rotation record")
	sub := ""
	rebuild := fs.Bool("rebuild", false, "project: rebuild from scratch")
	check := fs.Bool("check", false, "project: verify stored projection == rebuild")
	format := fs.String("format", "json", "incident: json|html|md")
	tokName := fs.String("name", "", "token create: token name")
	tokRole := fs.String("role", "writer", "token create: role (writer|viewer|auditor|admin)")
	rkProduct := fs.String("product", "", "keys enroll/list: product name (gate|proof|ledger|warrant|harbour|bench)")
	rkKeyID := fs.String("key-id", "", "keys enroll/revoke: receipt-signer key id")
	rkPubKey := fs.String("public-key", "", "keys enroll: base64 public key, or @file to read it from a file")
	rkAlg := fs.String("alg", "ed25519", "keys enroll: ed25519 | ecdsa-p256-sha256")
	rkReason := fs.String("reason", "", "keys revoke: reason recorded with the revocation")
	switch cmd {
	case "verify", "replay", "export", "anchor", "project", "incident":
		_ = fs.Parse(args)
	case "keys", "token":
		if len(args) == 0 {
			die("%s requires a subcommand", cmd)
		}
		sub = args[0]
		_ = fs.Parse(args[1:])
	case "-h", "--help", "help":
		fmt.Print(usage + opsUsage)
		return
	default:
		fmt.Fprint(os.Stderr, usage+opsUsage)
		os.Exit(2)
	}
	ctx := context.Background()
	st, err := store.Open(ctx, env("LEDGER_DATABASE_URL", "postgres://postgres:postgres@localhost:5432/ledger?sslmode=disable"))
	if err != nil {
		die("database: %v", err)
	}
	defer st.Close()
	if cmd == "token" {
		runToken(ctx, st, sub, *tokName, *tokRole, fs.Args())
		return
	}
	// verify/replay never create a key file; verify --anchors reads the keyring (trusted keys) if configured.
	var key ed25519.PrivateKey
	var keyring *anchor.Keyring
	if (cmd != "verify" && cmd != "replay") || (*withAnchors && os.Getenv("LEDGER_KEYRING_DIR") != "") {
		if key, keyring, err = anchor.LoadSigner(os.Getenv("LEDGER_SIGNING_KEY"), env("LEDGER_KEY_FILE", "ledger_ed25519.key"), os.Getenv("LEDGER_KEYRING_DIR")); err != nil {
			die("signing key: %v", err)
		}
	}
	acfg, err := anchoring.ConfigFromEnv(os.Getenv)
	if err != nil {
		die("anchoring config: %v", err)
	}
	if cmd == "anchor" && *external {
		acfg.AnchorDir = *dir
	}
	svc := acfg.Service(st, key, keyring, nil)
	if len(chains) == 0 && (cmd == "verify" || cmd == "anchor") {
		if chains, err = st.Chains(ctx); err != nil {
			die("%v", err)
		}
	}
	switch cmd {
	case "verify":
		if *withAnchors {
			failed := false
			var reps []anchoring.ChainReport
			for _, c := range chains {
				rep, err := svc.VerifyChainAnchors(ctx, c)
				if err != nil {
					die("%v", err)
				}
				failed = failed || !rep.OK
				reps = append(reps, rep)
				if !*asJSON {
					fmt.Print(anchoring.FormatReport(rep))
				}
			}
			if *asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				_ = enc.Encode(reps)
			}
			if failed {
				st.Close()
				os.Exit(1)
			}
			return
		}
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
		runIncident(ctx, st, *goal, *format, outFile, keyring)
	case "anchor":
		if *external {
			bad := false
			for _, c := range chains {
				res, err := svc.AnchorChain(ctx, c)
				if err != nil {
					bad = true
					fmt.Fprintf(os.Stderr, "FAILED  %s: %v\n", c, err)
					continue
				}
				fmt.Printf("anchored %s seq=%d head=%s key=%s receipts=%v\n", c, res.Seq, res.Head, res.KeyID, res.Receipts)
				for _, e := range res.Errors {
					fmt.Printf("  warning: %s\n", e)
				}
			}
			if bad {
				st.Close()
				os.Exit(1)
			}
			return
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
	case "keys":
		switch sub {
		case "list":
			if keyring != nil {
				fmt.Println("root-signing keyring (LEDGER_KEYRING_DIR):")
				for _, id := range keyring.IDs() {
					mark := "retired"
					if id == keyring.ActiveID() {
						mark = "active"
					}
					fmt.Printf("  %s  %s\n", id, mark)
				}
			}
			runKeysList(ctx, st, *rkProduct)
		case "rotate":
			if keyring == nil {
				die("keys rotate requires LEDGER_KEYRING_DIR")
			}
			rot, rec, err := svc.RotateKey(ctx, *operator, *keepOld)
			if err != nil {
				die("%v", err)
			}
			fmt.Printf("rotated %s -> %s (recorded as %s seq=%d)\n", rot.OldKeyID, rot.NewKeyID, rec.Chain, rec.Seq)
		case "enroll":
			runKeysEnroll(ctx, st, *rkProduct, *rkKeyID, *rkPubKey, *rkAlg, *operator)
		case "revoke":
			runKeysRevoke(ctx, st, *rkKeyID, *rkReason)
		default:
			die("keys requires list|rotate|enroll|revoke")
		}
	}
}
