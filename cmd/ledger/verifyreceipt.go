package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Celaris-dev1/Ledger/internal/receipt"
)

const verifyReceiptUsage = `  ledger verify-receipt [--file PATH] [--pubkey BASE64 --alg ed25519|ecdsa-p256-sha256]
                                         verify a stack-receipt/v1 envelope's structure and signature;
                                         reads from --file or stdin; without --pubkey, trusts the
                                         envelope's own signer_key_id only for structural checks and
                                         prints it without asserting trust (exit 1 either way on failure)
`

// runVerifyReceipt implements `ledger verify-receipt`. It never touches the database: a receipt
// is meant to be verifiable offline by anyone holding the signer's public key, independent of any
// one Ledger instance's storage.
func runVerifyReceipt(args []string) {
	fs := flag.NewFlagSet("verify-receipt", flag.ExitOnError)
	file := fs.String("file", "", "path to a JSON stack-receipt/v1 envelope (default: stdin)")
	pubkeyB64 := fs.String("pubkey", "", "base64 public key to verify against (required to assert trust)")
	alg := fs.String("alg", "ed25519", "signature algorithm: ed25519 | ecdsa-p256-sha256")
	asJSON := fs.Bool("json", false, "print a JSON result instead of text")
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
	if *pubkeyB64 == "" {
		// No key supplied: report what the envelope claims, but this is not a trust decision.
		result(*asJSON, false, env.SignerKeyID, "no --pubkey supplied: cannot assert trust; pass --pubkey (and --alg) to verify the signature")
		os.Exit(1)
	}
	pub, err := base64.StdEncoding.DecodeString(*pubkeyB64)
	if err != nil {
		die("verify-receipt: --pubkey: %v", err)
	}
	if err := receipt.Verify(env, *alg, pub); err != nil {
		result(*asJSON, false, env.SignerKeyID, err.Error())
		os.Exit(1)
	}
	result(*asJSON, true, env.SignerKeyID, "signature and structure verify")
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
