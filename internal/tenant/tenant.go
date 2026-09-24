// Package tenant scopes the record store to one tenant.
//
// A tenant's chains are stored under the physical name "t/<tenant>/<chain>" (the default
// tenant uses bare names), so the tenant is covered by every record hash. Scoped reads filter on
// the indexed `tenant` column, which the database derives from the physical name on insert.
// Callers only ever see logical chain names; a scoped store can neither name nor reach another
// tenant's chains.
package tenant

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/Celaris-dev1/Ledger/internal/store"
)

// Admin is the pseudo-tenant of an operator token that may read across tenants.
const Admin = "*"

var validID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// ValidID reports whether id is an acceptable tenant id.
func ValidID(id string) bool { return id == store.DefaultTenant || validID.MatchString(id) }

// Scoped is a tenant-scoped view of a *store.Store; it implements api.Backend.
type Scoped struct {
	St     *store.Store
	Tenant string
}

// New returns a scoped store (tenant "" = default).
func New(st *store.Store, tenant string) (*Scoped, error) {
	if tenant == "" {
		tenant = store.DefaultTenant
	}
	if !ValidID(tenant) {
		return nil, errors.New("invalid tenant id")
	}
	return &Scoped{St: st, Tenant: tenant}, nil
}

// Physical maps a logical chain name to its stored name. Logical names may not use the
// reserved "t/" prefix.
func (s *Scoped) Physical(chain string) (string, error) {
	if strings.HasPrefix(chain, "t/") {
		return "", &store.ValidationError{Msg: `chain names starting with "t/" are reserved for tenant namespaces`}
	}
	return store.TenantPrefix(s.Tenant) + chain, nil
}

// Logical strips the tenant prefix.
func Logical(chain string) string {
	if t := store.TenantOfChain(chain); t != store.DefaultTenant {
		return strings.TrimPrefix(chain, store.TenantPrefix(t))
	}
	return chain
}

func (s *Scoped) strip(recs []store.Record) []store.Record {
	// Defense in depth: the tenant column is derived, not hashed; only return rows whose hashed
	// chain name belongs to this tenant, even if the column was altered.
	kept := recs[:0]
	for _, r := range recs {
		if store.TenantOfChain(r.Chain) == s.Tenant {
			kept = append(kept, r)
		}
	}
	recs = kept
	for i := range recs {
		recs[i].Chain = Logical(recs[i].Chain)
	}
	return recs
}

func (s *Scoped) Append(ctx context.Context, req store.AppendRequest) (*store.Record, error) {
	p, err := s.Physical(req.Chain)
	if err != nil {
		return nil, err
	}
	req.Chain = p
	rec, err := s.St.Append(ctx, req)
	if rec != nil {
		rec.Chain = Logical(rec.Chain)
	}
	return rec, err
}

func (s *Scoped) List(ctx context.Context, q store.Query) ([]store.Record, error) {
	if q.Chain != "" {
		p, err := s.Physical(q.Chain)
		if err != nil {
			return []store.Record{}, nil
		}
		q.Chain = p
	}
	recs, err := s.St.ListTenant(ctx, s.Tenant, q)
	return s.strip(recs), err
}

func (s *Scoped) Replay(ctx context.Context, goalID string) ([]store.Record, error) {
	recs, err := s.St.ReplayTenant(ctx, s.Tenant, goalID)
	return s.strip(recs), err
}

func (s *Scoped) Verify(ctx context.Context, chain string) (store.VerifyResult, error) {
	p, err := s.Physical(chain)
	if err != nil {
		return store.VerifyResult{Chain: chain, OK: true}, nil
	}
	res, err := s.St.Verify(ctx, p)
	res.Chain = chain
	return res, err
}

func (s *Scoped) Head(ctx context.Context, chain string) (int64, string, error) {
	p, err := s.Physical(chain)
	if err != nil {
		return 0, "", nil
	}
	return s.St.Head(ctx, p)
}

func (s *Scoped) ChainRecords(ctx context.Context, chain string) ([]store.Record, error) {
	p, err := s.Physical(chain)
	if err != nil {
		return []store.Record{}, nil
	}
	recs, err := s.St.ChainRecords(ctx, p)
	return s.strip(recs), err
}

// Chains lists the tenant's logical chain names.
func (s *Scoped) Chains(ctx context.Context) ([]string, error) {
	cs, err := s.St.ChainsTenant(ctx, s.Tenant)
	for i := range cs {
		cs[i] = Logical(cs[i])
	}
	return cs, err
}

// ParseTokens parses LEDGER_TOKENS: "token1=tenantA,token2=tenantB,opstoken=*".
func ParseTokens(spec string) (map[string]string, error) {
	out := map[string]string{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		tok, ten, ok := strings.Cut(part, "=")
		tok, ten = strings.TrimSpace(tok), strings.TrimSpace(ten)
		if !ok || tok == "" || (ten != Admin && !ValidID(ten)) {
			return nil, errors.New("LEDGER_TOKENS must be token=tenant[,token=tenant...] (tenant [a-z0-9_-] or *)")
		}
		out[tok] = ten
	}
	return out, nil
}
