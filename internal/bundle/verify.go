package bundle

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"sort"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/anchoring"
)

// Report is the offline verification result for a whole bundle.
type Report struct {
	OK     bool                             `json:"ok"`
	Chains map[string]anchoring.ChainReport `json:"chains"`
	// Order lists chain names in the order they were checked, for stable human output.
	Order []string `json:"-"`
}

// Verify re-checks every chain in b exactly as `ledger verify --anchors` would online, using only
// what the bundle carries: no database, no network.
func Verify(b Bundle) (Report, error) {
	rep := Report{OK: true, Chains: map[string]anchoring.ChainReport{}}

	var trust anchor.TrustSet
	if len(b.Trust) > 0 {
		trust = anchor.TrustSet{}
		for id, b64 := range b.Trust {
			pub, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				return rep, fmt.Errorf("trust.json: key %q: %w", id, err)
			}
			trust[id] = ed25519.PublicKey(pub)
		}
	}

	var pool *x509.CertPool
	if len(b.TSARoots) > 0 {
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b.TSARoots) {
			return rep, fmt.Errorf("tsa_roots.pem: no certificates found")
		}
	}
	verifier := anchoring.Verifier{TSARoots: pool}

	names := make([]string, 0, len(b.Chains))
	for c := range b.Chains {
		names = append(names, c)
	}
	sort.Strings(names)
	rep.Order = names

	for _, name := range names {
		ch := b.Chains[name]
		cr := anchoring.VerifyChain(name, ch.Records, ch.Receipts, anchoring.Options{Verifier: verifier, Trust: trust})
		if trust == nil {
			cr.Warnings = append(cr.Warnings, "bundle carries no trust.json: root signatures were checked against their own embedded key only")
		}
		rep.Chains[name] = cr
		if !cr.OK {
			rep.OK = false
		}
	}
	if len(names) == 0 {
		rep.OK = false
	}
	return rep, nil
}
