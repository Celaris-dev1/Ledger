package keys

import (
	"context"
	"crypto/ed25519"
	"fmt"
)

// SignerFromEnv picks the root/document signer from LEDGER_SIGNER:
//
//	file (default)  the local Ed25519 key / keyring (passed in as local)
//	vault           LEDGER_VAULT_ADDR, LEDGER_VAULT_TOKEN, LEDGER_VAULT_TRANSIT_KEY,
//	                LEDGER_VAULT_TRANSIT_MOUNT (default transit), LEDGER_VAULT_NAMESPACE
//	awskms          LEDGER_KMS_KEY_ID, AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
//	                AWS_SESSION_TOKEN, LEDGER_KMS_ENDPOINT (optional)
func SignerFromEnv(ctx context.Context, getenv func(string) string, local ed25519.PrivateKey) (Signer, error) {
	switch getenv("LEDGER_SIGNER") {
	case "", "file":
		if local == nil {
			return nil, fmt.Errorf("no local signing key")
		}
		return Ed25519Signer{Key: local}, nil
	case "vault":
		return NewVaultTransit(ctx, &VaultTransit{Addr: getenv("LEDGER_VAULT_ADDR"), Token: getenv("LEDGER_VAULT_TOKEN"),
			Namespace: getenv("LEDGER_VAULT_NAMESPACE"), Mount: getenv("LEDGER_VAULT_TRANSIT_MOUNT"), KeyName: getenv("LEDGER_VAULT_TRANSIT_KEY")})
	case "awskms":
		region := getenv("AWS_REGION")
		if region == "" {
			region = getenv("AWS_DEFAULT_REGION")
		}
		return NewAWSKMS(ctx, &AWSKMS{Region: region, KeyRef: getenv("LEDGER_KMS_KEY_ID"), AccessKey: getenv("AWS_ACCESS_KEY_ID"),
			SecretKey: getenv("AWS_SECRET_ACCESS_KEY"), SessionToken: getenv("AWS_SESSION_TOKEN"), Endpoint: getenv("LEDGER_KMS_ENDPOINT")})
	}
	return nil, fmt.Errorf("LEDGER_SIGNER must be file|vault|awskms, got %q", getenv("LEDGER_SIGNER"))
}
