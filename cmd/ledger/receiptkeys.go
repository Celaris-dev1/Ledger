package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/Celaris-dev1/Ledger/internal/receiptkeys"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

// resolvePublicKey accepts either a raw base64 string or "@path/to/file" (the file's contents,
// trimmed, are the base64).
func resolvePublicKey(v string) (string, error) {
	if !strings.HasPrefix(v, "@") {
		return v, nil
	}
	b, err := os.ReadFile(v[1:])
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func runKeysEnroll(ctx context.Context, st *store.Store, product, keyID, pubKeyArg, alg, operator string) {
	if product == "" || keyID == "" || pubKeyArg == "" {
		die("keys enroll requires --product, --key-id and --public-key")
	}
	pub, err := resolvePublicKey(pubKeyArg)
	if err != nil {
		die("keys enroll: --public-key: %v", err)
	}
	if _, err := base64.StdEncoding.DecodeString(pub); err != nil {
		die("keys enroll: --public-key is not valid base64: %v", err)
	}
	rk := receiptkeys.Open(st.Pool)
	k, err := rk.Enroll(ctx, receiptkeys.DefaultTenant, receiptkeys.Key{
		KeyID: keyID, Product: product, Alg: alg, PublicKey: pub, EnrolledBy: operator,
	})
	if err != nil {
		die("keys enroll: %v", err)
	}
	fmt.Printf("enrolled %s (product=%s alg=%s) at %s\n", k.KeyID, k.Product, k.Alg, k.EnrolledAt.Format("2006-01-02T15:04:05Z"))
}

func runKeysRevoke(ctx context.Context, st *store.Store, keyID, reason string) {
	if keyID == "" {
		die("keys revoke requires --key-id")
	}
	rk := receiptkeys.Open(st.Pool)
	if err := rk.Revoke(ctx, receiptkeys.DefaultTenant, keyID, reason); err != nil {
		die("keys revoke: %v", err)
	}
	fmt.Printf("revoked %s: %s\n", keyID, reason)
}

func runKeysList(ctx context.Context, st *store.Store, product string) {
	rk := receiptkeys.Open(st.Pool)
	ks, err := rk.List(ctx, receiptkeys.DefaultTenant, product)
	if err != nil {
		die("keys list: %v", err)
	}
	fmt.Println("enrolled stack-receipt trust keyring:")
	if len(ks) == 0 {
		fmt.Println("  (none enrolled)")
		return
	}
	for _, k := range ks {
		status := "active"
		if k.RevokedAt != nil {
			status = "revoked (" + k.Reason + ") at " + k.RevokedAt.Format("2006-01-02T15:04:05Z")
		}
		fmt.Printf("  %-24s product=%-10s alg=%-16s enrolled=%s  %s\n", k.KeyID, k.Product, k.Alg, k.EnrolledAt.Format("2006-01-02T15:04:05Z"), status)
	}
}
