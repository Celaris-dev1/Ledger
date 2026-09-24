package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Celaris-dev1/Ledger/internal/receipt"
	"github.com/Celaris-dev1/Ledger/internal/receiptkeys"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

const verifyReceiptUsage = `  ledger verify-receipt [--file PATH] [--pubkey BASE64 --alg ed25519|ecdsa-p256-sha256] [--no-db]
                                         verify a stack-receipt/v1 envelope's structure and signature;
                                         reads from --file or stdin. With --pubkey, verifies against
                                         that key. Without it, looks the envelope's signer_key_id up in
                                         the enrolled receipt-key keyring (LEDGER_DATABASE_URL; skip with
                                         --no-db to stay fully offline) and reports trusted:true only for
                                         an enrolled, unrevoked key (exit 1 either way on failure)
`

// runVerifyReceipt implements `ledger verify-receipt`. With --pubkey (or --no-db), it never
// touches the database: a receipt is meant to be verifiable offline by anyone holding the
// signer's public key, independent of any one Ledger instance's storage. Without --pubkey, it
// defaults to looking the key up in the enrolled receipt-key keyring so an operator can check a
// receipt against "keys we actually enrolled" without hunting down the raw public key by hand.
func runVerifyReceipt(args []string) {
	fs := flag.NewFlagSet("verify-receipt", flag.ExitOnError)
	file := fs.String("file", "", "path to a JSON stack-receipt/v1 envelope (default: stdin)")
	pubkeyB64 := fs.String("pubkey", "", "base64 public key to verify against (required to assert trust)")
	alg := fs.String("alg", "ed25519", "signature algorithm: ed25519 | ecdsa-p256-sha256")
	asJSON := fs.Bool("json", false, "print a JSON result instead of text")
	noDB := fs.Bool("no-db", false, "do not consult the enrolled receipt-key keyring")
	_ = fs.Parse(args)

	var raw []byte
	var err error
	if *file != "" {
		raw, err = os.ReadFile(*file)
	} else {
		raw, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		die("verify-receipt: %v", err)
	}
	var env receipt.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		result(*asJSON, false, "", fmt.Sprintf("malformed JSON: %v", err))
		os.Exit(1)
	}

	var pub []byte
	usedAlg := *alg
	trusted := false
	switch {
	case *pubkeyB64 != "":
		pub, err = base64.StdEncoding.DecodeString(*pubkeyB64)
		if err != nil {
			die("verify-receipt: --pubkey: %v", err)
		}
	case *noDB || os.Getenv("LEDGER_DATABASE_URL") == "":
		result(*asJSON, false, env.SignerKeyID, "no --pubkey supplied and no enrolled-key lookup available: cannot assert trust; pass --pubkey (and --alg), or set LEDGER_DATABASE_URL")
		os.Exit(1)
	default:
		ctx := context.Background()
		st, err := store.Open(ctx, os.Getenv("LEDGER_DATABASE_URL"))
		if err != nil {
			die("verify-receipt: database: %v", err)
		}
		defer st.Close()
		rk := receiptkeys.Open(st.Pool)
		gotAlg, gotPub, ok := rk.Trust(ctx, receiptkeys.DefaultTenant)(env.SignerKeyID, env.IssuedAt)
		if !ok {
			result(*asJSON, false, env.SignerKeyID, "signer_key_id not enrolled, or revoked as of this receipt's issued_at")
			os.Exit(1)
		}
		usedAlg, pub, trusted = gotAlg, gotPub, true
	}
	if err := receipt.Verify(env, usedAlg, pub); err != nil {
		result(*asJSON, false, env.SignerKeyID, err.Error())
		os.Exit(1)
	}
	detail := "signature and structure verify"
	if trusted {
		detail += " (key enrolled and unrevoked)"
	}
	result(*asJSON, true, env.SignerKeyID, detail)
}

func result(asJSON bool, ok bool, keyID, detail string) {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		_ = enc.Encode(map[string]any{"ok": ok, "signer_key_id": keyID, "detail": detail})
		return
	}
	status := "OK"
	if !ok {
		status = "FAIL"
	}
	fmt.Printf("%-4s signer_key_id=%s %s\n", status, keyID, detail)
}
