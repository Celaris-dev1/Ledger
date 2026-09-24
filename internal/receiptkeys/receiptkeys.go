// Package receiptkeys manages the trust keyring for stack-receipt/v1 envelopes: which product
// signing keys are enrolled, and since when a key was revoked. It backs `ledger keys
// enroll|revoke`, the operator-only HTTP endpoints, and the TrustFunc that `ledger incident` and
// `ledger verify-receipt` load by default (see internal/incident.WithTrust,
// internal/receipt.Verify).
package receiptkeys

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/keys"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DefaultTenant is used when the caller has no tenant scoping.
const DefaultTenant = "default"

// Key is one enrolled receipt-signer key.
type Key struct {
	KeyID      string     `json:"key_id"`
	Tenant     string     `json:"tenant"`
	Product    string     `json:"product"`
	Alg        string     `json:"alg"`
	PublicKey  string     `json:"public_key"` // base64
	EnrolledAt time.Time  `json:"enrolled_at"`
	EnrolledBy string     `json:"enrolled_by,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	Reason     string     `json:"reason,omitempty"`
}

// Revoked reports whether the key was revoked as of at (zero at means "now").
func (k Key) RevokedAsOf(at time.Time) bool {
	if k.RevokedAt == nil {
		return false
	}
	if at.IsZero() {
		return true
	}
	return !at.Before(*k.RevokedAt)
}

var (
	// ErrNotFound is returned by Revoke when the key id is not enrolled in the tenant.
	ErrNotFound = errors.New("receiptkeys: key not enrolled")
	// ErrExists is returned by Enroll when the key id is already enrolled in the tenant.
	ErrExists = errors.New("receiptkeys: key id already enrolled")
)

// Store is the Postgres-backed receipt-key keyring. The zero value is not usable; use Open or
// wrap an existing pool with &Store{Pool: pool}.
type Store struct{ Pool *pgxpool.Pool }

// Open wraps an existing pool (the same pool as store.Store; migrations create the table).
func Open(pool *pgxpool.Pool) *Store { return &Store{Pool: pool} }

// Enroll registers a new key. keyID is caller-supplied (products mint their own ids, e.g.
// "gate-2026-01") so it must be non-empty and unique per tenant.
func (s *Store) Enroll(ctx context.Context, tenant string, k Key) (*Key, error) {
	if tenant == "" {
		tenant = DefaultTenant
	}
	if k.KeyID == "" {
		return nil, errors.New("receiptkeys: key_id is required")
	}
	if k.Product == "" {
		return nil, errors.New("receiptkeys: product is required")
	}
	alg := keys.NormalizeAlg(k.Alg)
	if alg != keys.AlgEd25519 && alg != keys.AlgECDSAP256 {
		return nil, fmt.Errorf("receiptkeys: unknown alg %q (want %q or %q)", k.Alg, keys.AlgEd25519, keys.AlgECDSAP256)
	}
	pub, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil || len(pub) == 0 {
		return nil, errors.New("receiptkeys: public_key must be base64")
	}
	if k.EnrolledAt.IsZero() {
		k.EnrolledAt = time.Now().UTC()
	}
	_, err = s.Pool.Exec(ctx, `
		INSERT INTO receipt_keys (key_id, tenant, product, alg, public_key, enrolled_at, enrolled_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		k.KeyID, tenant, k.Product, alg, k.PublicKey, k.EnrolledAt, k.EnrolledBy)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrExists
		}
		return nil, err
	}
	k.Tenant, k.Alg = tenant, alg
	return &k, nil
}

// List returns every enrolled key for tenant (including revoked ones), newest first. product,
// when non-empty, filters to that product.
func (s *Store) List(ctx context.Context, tenant, product string) ([]Key, error) {
	if tenant == "" {
		tenant = DefaultTenant
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT key_id, tenant, product, alg, public_key, enrolled_at, enrolled_by, revoked_at, reason
		FROM receipt_keys WHERE tenant=$1 AND ($2='' OR product=$2) ORDER BY enrolled_at DESC, key_id`,
		tenant, product)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Key
	for rows.Next() {
		var k Key
		if err := rows.Scan(&k.KeyID, &k.Tenant, &k.Product, &k.Alg, &k.PublicKey, &k.EnrolledAt, &k.EnrolledBy, &k.RevokedAt, &k.Reason); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// Get returns one key by id, or nil if not enrolled in tenant.
func (s *Store) Get(ctx context.Context, tenant, keyID string) (*Key, error) {
	if tenant == "" {
		tenant = DefaultTenant
	}
	var k Key
	err := s.Pool.QueryRow(ctx, `
		SELECT key_id, tenant, product, alg, public_key, enrolled_at, enrolled_by, revoked_at, reason
		FROM receipt_keys WHERE tenant=$1 AND key_id=$2`, tenant, keyID).
		Scan(&k.KeyID, &k.Tenant, &k.Product, &k.Alg, &k.PublicKey, &k.EnrolledAt, &k.EnrolledBy, &k.RevokedAt, &k.Reason)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// Revoke marks a key revoked as of now (or updates the reason if already revoked). Receipts
// issued after the revocation timestamp are rejected by the default TrustFunc; receipts issued
// before it remain trusted, since the key was good at the time.
func (s *Store) Revoke(ctx context.Context, tenant, keyID, reason string) error {
	if tenant == "" {
		tenant = DefaultTenant
	}
	tag, err := s.Pool.Exec(ctx, `
		UPDATE receipt_keys SET revoked_at = COALESCE(revoked_at, now()), reason=$3
		WHERE tenant=$1 AND key_id=$2`, tenant, keyID, reason)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Trust returns a resolver shaped for internal/incident.WithTrust: for a given key id and the
// receipt's own issued_at, it reports ok=true only for a key enrolled in tenant and not revoked
// as of issuedAt. A key revoked before issuedAt is rejected (ok=false); an unknown key id is
// also ok=false, matching the documented default: unknown -> trusted:false.
func (s *Store) Trust(ctx context.Context, tenant string) func(keyID string, issuedAt time.Time) (alg string, pub []byte, ok bool) {
	return func(keyID string, issuedAt time.Time) (string, []byte, bool) {
		k, err := s.Get(ctx, tenant, keyID)
		if err != nil || k == nil {
			return "", nil, false
		}
		if k.RevokedAsOf(issuedAt) {
			return "", nil, false
		}
		pub, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil {
			return "", nil, false
		}
		return k.Alg, pub, true
	}
}

func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}
