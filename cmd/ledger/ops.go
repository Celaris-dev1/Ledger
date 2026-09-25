package main

// Compliance / ops commands (stream: compliance): regime auditor packs, retention and legal
// holds, crypto-shredding erasure, signed backup/restore and the load test.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/anchoring"
	"github.com/Celaris-dev1/Ledger/internal/backup"
	"github.com/Celaris-dev1/Ledger/internal/bench"
	"github.com/Celaris-dev1/Ledger/internal/compliance"
	"github.com/Celaris-dev1/Ledger/internal/keys"
	"github.com/Celaris-dev1/Ledger/internal/license"
	"github.com/Celaris-dev1/Ledger/internal/retention"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

const opsUsage = `
compliance / ops:
  ledger export --regime eu-ai-act|soc2|hipaa [--version V] [--from T] [--to T] [--goal ID | --chain NAME ...]
                [--out DIR] [--formats json,html,pdf]
                                         signed auditor pack from a versioned regime template (report.json,
                                         report.html, report.pdf with the signed JSON embedded)
  ledger export --verify FILE            verify a pack's document hash + signature (report.json or report.pdf)
  ledger retention set --chain NAME|* --regime R [--min 6y] [--reason TEXT] [--operator ID]
  ledger retention status [--json]       per-chain policy, records past minimum retention (never deleted), holds
  ledger hold create --id ID --reason TEXT (--chain NAME ... | --subject S ... | --all) [--operator ID]
  ledger hold release --id ID --reason TEXT [--operator ID]
  ledger hold list
  ledger erase --subject S --reason TEXT [--basis TEXT] [--override-retention TEXT] [--operator ID]
                                         crypto-shred a data subject (LEDGER_DATA_KEY_DIR); blocked by legal holds
  ledger backup --out DIR [--operator ID]
                                         consistent signed logical backup (records, receipts, key metadata)
  ledger restore --in DIR [--verify-only] [--allow-untrusted]
                                         verify everything, then restore into an empty ledger
  ledger bench [--writers 16] [--chains 64] [--records 20000] [--payload 256] [--verify-n 100000] [--compare] [--json]
                                         load test in a throwaway schema of LEDGER_DATABASE_URL

env: LEDGER_SIGNER=file|vault|awskms (+ LEDGER_VAULT_*, LEDGER_KMS_KEY_ID, AWS_*), LEDGER_DATA_KEY_DIR
`

func dbURL() string {
	return env("LEDGER_DATABASE_URL", "postgres://postgres:postgres@localhost:5432/ledger?sslmode=disable")
}

func openStore(ctx context.Context) *store.Store {
	st, err := store.Open(ctx, dbURL())
	if err != nil {
		die("database: %v", err)
	}
	return st
}

// signer resolves the document/root signer (LEDGER_SIGNER) and the local keyring.
func signer(ctx context.Context) (keys.Signer, *anchor.Keyring) {
	var kr *anchor.Keyring
	if s := os.Getenv("LEDGER_SIGNER"); s == "" || s == "file" {
		k, ring, err := anchor.LoadSigner(os.Getenv("LEDGER_SIGNING_KEY"), env("LEDGER_KEY_FILE", "ledger_ed25519.key"), os.Getenv("LEDGER_KEYRING_DIR"))
		if err != nil {
			die("signing key: %v", err)
		}
		return keys.Ed25519Signer{Key: k}, ring
	}
	if err := license.Require(license.FeatureKMSSigner); err != nil {
		die("%v", err)
	}
	s, err := keys.SignerFromEnv(ctx, os.Getenv, nil)
	if err != nil {
		die("signer: %v", err)
	}
	if d := os.Getenv("LEDGER_KEYRING_DIR"); d != "" {
		kr, _ = anchor.OpenKeyring(d, nil)
	}
	return s, kr
}

// trustSet: keyring public keys (+ the configured external signer) when available.
func trustSet(ctx context.Context) anchor.TrustSet {
	ts := anchor.TrustSet{}
	if d := os.Getenv("LEDGER_KEYRING_DIR"); d != "" {
		if kr, err := anchor.OpenKeyring(d, nil); err == nil {
			for id, p := range kr.Public {
				ts[id] = p
			}
		}
	}
	if s := os.Getenv("LEDGER_SIGNER"); s == "vault" || s == "awskms" {
		if sg, err := keys.SignerFromEnv(ctx, os.Getenv, nil); err == nil {
			ts[sg.KeyID()] = sg.PublicKey()
		}
	}
	if len(ts) == 0 {
		return nil
	}
	return ts
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, l := range []string{time.RFC3339Nano, "2006-01-02"} {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC()
		}
	}
	die("bad time %q (RFC 3339 or YYYY-MM-DD)", s)
	return time.Time{}
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == "--"+name || a == "-"+name || strings.HasPrefix(a, "--"+name+"=") || strings.HasPrefix(a, "-"+name+"=") {
			return true
		}
	}
	return false
}

// runOps handles the compliance/ops commands; it returns false for commands it does not own.
func runOps(cmd string, args []string) bool {
	ctx := context.Background()
	switch {
	case cmd == "export" && (hasFlag(args, "regime") || hasFlag(args, "verify")):
		runRegimeExport(ctx, args)
	case cmd == "retention":
		runRetention(ctx, args)
	case cmd == "hold":
		runHold(ctx, args)
	case cmd == "erase":
		runErase(ctx, args)
	case cmd == "backup":
		runBackup(ctx, args)
	case cmd == "restore":
		runRestore(ctx, args)
	case cmd == "bench":
		runBench(ctx, args)
	default:
		return false
	}
	return true
}

func runRegimeExport(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	var chains multi
	fs.Var(&chains, "chain", "chain (repeatable)")
	regime := fs.String("regime", "", "eu-ai-act|soc2|hipaa")
	version := fs.String("version", "", "template version (default latest)")
	from := fs.String("from", "", "window start (inclusive)")
	to := fs.String("to", "", "window end (exclusive)")
	goal := fs.String("goal", "", "goal id")
	out := fs.String("out", "auditor-pack", "output directory")
	formats := fs.String("formats", "json,html,pdf", "comma-separated formats")
	verify := fs.String("verify", "", "verify a report.json / report.pdf")
	_ = fs.Parse(args)
	if *verify != "" {
		b, err := os.ReadFile(*verify)
		if err != nil {
			die("%v", err)
		}
		var r compliance.Report
		trust := trustSet(ctx)
		if strings.HasPrefix(string(b), "%PDF") {
			// The whole PDF, not just its embedded report, must match the signature.
			r, err = compliance.VerifyPDF(b, trust)
		} else if err = json.Unmarshal(b, &r); err != nil {
			die("%v", err)
		} else {
			err = compliance.Verify(r, trust)
		}
		if err != nil {
			fmt.Printf("INVALID  %s: %v\n", *verify, err)
			os.Exit(1)
		}
		note := "signing key trusted via keyring"
		if trust == nil {
			note = "no keyring configured: checked against the embedded public key only"
		}
		fmt.Printf("OK  %s  template=%s document_hash=%s key=%s (%s)\n", *verify, r.Template, r.DocumentHash, r.Signature.KeyID, note)
		return
	}
	if err := license.Require(license.FeatureComplianceExport); err != nil {
		die("%v", err)
	}
	tp, err := compliance.Lookup(*regime, *version)
	if err != nil {
		die("%v", err)
	}
	st := openStore(ctx)
	defer st.Close()
	sg, kr := signer(ctx)
	acfg, err := anchoring.ConfigFromEnv(os.Getenv)
	if err != nil {
		die("anchoring config: %v", err)
	}
	g := &compliance.Gatherer{Store: st, Anchors: acfg.Service(st, anchorKey(sg), kr, nil), Signer: sg}
	ev, err := g.Gather(ctx, compliance.Scope{Chains: chains, GoalID: *goal, From: parseTime(*from), To: parseTime(*to)})
	if err != nil {
		die("%v", err)
	}
	rep := compliance.Evaluate(tp, ev)
	if err := compliance.Sign(ctx, &rep, sg); err != nil {
		die("sign: %v", err)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		die("%v", err)
	}
	var wrote []string
	for _, f := range strings.Split(*formats, ",") {
		p := filepath.Join(*out, "report."+strings.TrimSpace(f))
		var err error
		switch strings.TrimSpace(f) {
		case "json":
			err = writeFile(p, func(fh *os.File) error { return compliance.WriteJSON(fh, rep) })
		case "html":
			err = writeFile(p, func(fh *os.File) error { return compliance.WriteHTML(fh, rep) })
		case "pdf":
			var b []byte
			if b, err = compliance.RenderPDF(rep); err == nil {
				err = os.WriteFile(p, b, 0o644)
			}
		default:
			die("unknown format %q", f)
		}
		if err != nil {
			die("%s: %v", p, err)
		}
		wrote = append(wrote, p)
	}
	fmt.Printf("%s: %d pass, %d gap, %d manual over %d records; document_hash=%s signed by %s\n  %s\n",
		rep.Template, rep.Totals.Pass, rep.Totals.Gap, rep.Totals.Manual, rep.RecordCount, rep.DocumentHash, rep.Signature.KeyID, strings.Join(wrote, "\n  "))
}

// anchorKey returns the Ed25519 key for the anchoring service when the signer is local
// (external anchoring keeps using the keyring; KMS/Vault sign roots and documents).
func anchorKey(s keys.Signer) ed25519.PrivateKey {
	if e, ok := s.(keys.Ed25519Signer); ok {
		return e.Key
	}
	return nil
}

func writeFile(p string, fn func(*os.File) error) error {
	f, err := os.Create(p)
	if err != nil {
		return err
	}
	if err := fn(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func runRetention(ctx context.Context, args []string) {
	if len(args) == 0 {
		die("retention requires set|status")
	}
	fs := flag.NewFlagSet("retention", flag.ExitOnError)
	chain := fs.String("chain", "", "chain name or *")
	regime := fs.String("regime", "", "hipaa|eu-ai-act|soc2")
	min := fs.String("min", "", "minimum retention (e.g. 6y, 18m, 400d); default: regime minimum")
	reason := fs.String("reason", "", "reason")
	operator := fs.String("operator", env("USER", "operator"), "human operator id")
	asJSON := fs.Bool("json", false, "JSON output")
	_ = fs.Parse(args[1:])
	st := openStore(ctx)
	defer st.Close()
	svc := &retention.Service{Store: st}
	switch args[0] {
	case "set":
		rec, err := svc.SetPolicy(ctx, retention.Policy{Chain: *chain, Regime: *regime, MinRetention: *min, Reason: *reason}, *operator)
		if err != nil {
			die("%v", err)
		}
		fmt.Printf("retention policy for %s recorded as %s seq=%d\n", *chain, rec.Chain, rec.Seq)
	case "status":
		sts, err := svc.Status(ctx)
		if err != nil {
			die("%v", err)
		}
		if *asJSON {
			_ = json.NewEncoder(os.Stdout).Encode(sts)
			return
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "CHAIN\tPOLICY\tREGIME\tRECORDS\tOLDEST\tPAST-MINIMUM (eligible, never deleted)\tHOLD")
		for _, s := range sts {
			pol := s.Policy
			if s.NoPolicyWarning {
				pol = "NONE"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%d\t%s\n", s.Chain, pol, s.Regime, s.Records, s.Oldest, s.PastRetention, s.HeldBy)
		}
		tw.Flush()
	default:
		die("retention requires set|status")
	}
}

func runHold(ctx context.Context, args []string) {
	if len(args) == 0 {
		die("hold requires create|release|list")
	}
	fs := flag.NewFlagSet("hold", flag.ExitOnError)
	var chains, subjects multi
	fs.Var(&chains, "chain", "chain in scope (repeatable)")
	fs.Var(&subjects, "subject", "data subject in scope (repeatable; stored as its key id)")
	id := fs.String("id", "", "hold id")
	reason := fs.String("reason", "", "reason")
	all := fs.Bool("all", false, "hold everything")
	operator := fs.String("operator", env("USER", "operator"), "human operator id")
	_ = fs.Parse(args[1:])
	st := openStore(ctx)
	defer st.Close()
	svc := &retention.Service{Store: st}
	switch args[0] {
	case "create":
		ks := &keys.FileDataKeyStore{}
		var sk []string
		for _, s := range subjects {
			sk = append(sk, ks.KeyIDFor(s))
		}
		rec, err := svc.CreateHold(ctx, retention.Hold{ID: *id, Reason: *reason, Chains: chains, SubjectKeys: sk, All: *all}, *operator)
		if err != nil {
			die("%v", err)
		}
		fmt.Printf("legal hold %s created (%s seq=%d)\n", *id, rec.Chain, rec.Seq)
	case "release":
		rec, err := svc.ReleaseHold(ctx, *id, *reason, *operator)
		if err != nil {
			die("%v", err)
		}
		fmt.Printf("legal hold %s released (%s seq=%d)\n", *id, rec.Chain, rec.Seq)
	case "list":
		s, err := svc.State(ctx)
		if err != nil {
			die("%v", err)
		}
		for _, h := range s.Holds {
			state := "ACTIVE"
			if h.Released {
				state = "released " + h.ReleasedAt + " by " + h.ReleasedBy + ": " + h.ReleaseNote
			}
			scope := "all"
			if !h.All {
				scope = strings.Join(append(append([]string{}, h.Chains...), h.SubjectKeys...), ",")
			}
			fmt.Printf("%s  %s  scope=%s  by %s at %s  %s\n", h.ID, h.Reason, scope, h.CreatedBy, h.CreatedAt, state)
		}
	default:
		die("hold requires create|release|list")
	}
}

func dataKeys() keys.DataKeyStore {
	d := os.Getenv("LEDGER_DATA_KEY_DIR")
	if d == "" {
		die("LEDGER_DATA_KEY_DIR is not set (payload encryption / erasure not configured)")
	}
	return &keys.FileDataKeyStore{Dir: d}
}

func runErase(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("erase", flag.ExitOnError)
	subject := fs.String("subject", "", "data subject id")
	reason := fs.String("reason", "", "reason / request reference")
	basis := fs.String("basis", "", "legal basis, e.g. GDPR Art. 17")
	override := fs.String("override-retention", "", "justification to shred inside a minimum-retention period")
	operator := fs.String("operator", env("USER", "operator"), "human operator id")
	_ = fs.Parse(args)
	st := openStore(ctx)
	defer st.Close()
	svc := &retention.Service{Store: st, DataKeys: dataKeys()}
	rec, e, err := svc.Erase(ctx, retention.EraseRequest{Subject: *subject, Reason: *reason, LegalBasis: *basis, Operator: *operator, OverrideRetention: *override})
	if err != nil {
		die("%v", err)
	}
	fmt.Printf("crypto-shredded %s: %d record payload(s) in %v are now unreadable; recorded as %s seq=%d (no record was edited or deleted)\n",
		e.SubjectKeyID, e.RecordsAffected, e.Chains, rec.Type, rec.Seq)
}

func runBackup(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	out := fs.String("out", "", "backup directory (must be new or empty)")
	operator := fs.String("operator", env("USER", "operator"), "human operator id")
	_ = fs.Parse(args)
	if *out == "" {
		die("backup requires --out DIR")
	}
	st := openStore(ctx)
	defer st.Close()
	sg, kr := signer(ctx)
	m, err := backup.Create(ctx, st, *out, backup.Options{Signer: sg, Keyring: kr})
	if err != nil {
		die("backup: %v", err)
	}
	if _, err := backup.Record(ctx, st, m, *out, *operator); err != nil {
		die("backup written but not recorded: %v", err)
	}
	fmt.Printf("backup %s: %d chains, %d records, %d anchor receipts; manifest %s signed by %s\n", *out, len(m.Chains), m.Records, m.Receipts, m.ManifestHash, m.Signature.KeyID)
}

func runRestore(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	in := fs.String("in", "", "backup directory")
	verifyOnly := fs.Bool("verify-only", false, "verify without restoring")
	allowUntrusted := fs.Bool("allow-untrusted", false, "accept a manifest key not in LEDGER_KEYRING_DIR / the configured signer")
	_ = fs.Parse(args)
	if *in == "" {
		die("restore requires --in DIR")
	}
	trust := trustSet(ctx)
	if trust == nil && !*allowUntrusted {
		die("no trusted keys (set LEDGER_KEYRING_DIR or LEDGER_SIGNER) — pass --allow-untrusted to accept the key named in the manifest")
	}
	acfg, err := anchoring.ConfigFromEnv(os.Getenv)
	if err != nil {
		die("anchoring config: %v", err)
	}
	opt := backup.VerifyOptions{Trust: trust, Verifier: acfg.Service(nil, nil, nil, nil).Verifier}
	var L *backup.Loaded
	if *verifyOnly {
		L, err = backup.Load(*in, opt)
	} else {
		st := openStore(ctx)
		defer st.Close()
		L, err = backup.Restore(ctx, st, *in, opt)
	}
	if err != nil {
		die("%v", err)
	}
	for _, w := range L.Warnings {
		fmt.Printf("warning: %s\n", w)
	}
	verb := "restored"
	if *verifyOnly {
		verb = "verified"
	}
	fmt.Printf("%s %d chains, %d records, %d anchor receipts (manifest %s, key %s); run `ledger project --rebuild` to rebuild projections\n",
		verb, len(L.Manifest.Chains), L.Manifest.Records, L.Manifest.Receipts, L.Manifest.ManifestHash, L.Manifest.Signature.KeyID)
}

func runBench(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	writers := fs.Int("writers", 16, "concurrent writers")
	chains := fs.Int("chains", 64, "chains")
	records := fs.Int("records", 20000, "records to append")
	payload := fs.Int("payload", 256, "payload padding bytes")
	verifyN := fs.Int("verify-n", 100000, "length of the long chain for the verify benchmark (0 = skip)")
	compare := fs.Bool("compare", false, "also time the previous load-all + sequential verification")
	asJSON := fs.Bool("json", false, "JSON output")
	_ = fs.Parse(args)
	st, done, err := bench.Scratch(ctx, dbURL())
	if err != nil {
		die("bench: %v", err)
	}
	defer done()
	out := map[string]any{}
	if *records > 0 {
		r, err := bench.Append(ctx, st, *writers, *chains, *records, *payload)
		if err != nil {
			done()
			die("bench: %v", err)
		}
		out["append"] = r
		if !*asJSON {
			fmt.Println(r)
		}
	}
	if *verifyN > 0 {
		v, err := bench.Verify(ctx, st, *verifyN, *compare)
		if err != nil {
			done()
			die("bench: %v", err)
		}
		out["verify"] = v
		if !*asJSON {
			fmt.Println(v)
		}
	}
	if *asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(out)
	}
}
