package store

import (
	"context"
	"fmt"
	"testing"
)

// Streaming verification must give the same verdicts as VerifyRecords, including when the
// break sits exactly on or next to a page boundary.
func TestVerifyStreamMatchesInMemory(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	for i := 1; i <= 23; i++ {
		if _, err := s.Append(ctx, req("c", "t", "", fmt.Sprintf(`{"i":%d}`, i))); err != nil {
			t.Fatal(err)
		}
	}
	for _, batch := range []int{1, 5, 7, 23, 100} {
		res, err := s.VerifyStream(ctx, "c", batch)
		if err != nil || !res.OK || res.Length != 23 {
			t.Fatalf("batch %d: %+v %v", batch, res, err)
		}
		recs, _ := s.ChainRecords(ctx, "c")
		if want := VerifyRecords("c", recs); want.Head != res.Head {
			t.Fatal("head mismatch")
		}
	}
	// tamper seq 10 (bypassing the append-only trigger as a DB superuser would)
	tx, _ := s.Pool.Begin(ctx)
	_, _ = tx.Exec(ctx, `ALTER TABLE records DISABLE TRIGGER records_append_only`)
	if _, err := tx.Exec(ctx, `UPDATE records SET payload='{"i":999}' WHERE chain='c' AND seq=10`); err != nil {
		t.Fatal(err)
	}
	_, _ = tx.Exec(ctx, `ALTER TABLE records ENABLE TRIGGER records_append_only`)
	_ = tx.Commit(ctx)
	for _, batch := range []int{1, 5, 9, 10, 100} {
		res, err := s.VerifyStream(ctx, "c", batch)
		if err != nil || res.OK || res.BrokenAt == nil || *res.BrokenAt != 10 || res.Length != 23 {
			t.Fatalf("batch %d: %+v %v", batch, res, err)
		}
	}
}

func TestTenantColumnDerivedFromChainName(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	for _, c := range []string{"gate", "t/acme/gate", "t/globex/gate"} {
		if _, err := s.Append(ctx, req(c, "t", "g1", `{}`)); err != nil {
			t.Fatal(err)
		}
	}
	for tenant, want := range map[string]string{"default": "gate", "acme": "t/acme/gate", "globex": "t/globex/gate"} {
		recs, err := s.ListTenant(ctx, tenant, Query{})
		if err != nil || len(recs) != 1 || recs[0].Chain != want {
			t.Fatalf("%s: %v %+v", tenant, err, recs)
		}
		rp, _ := s.ReplayTenant(ctx, tenant, "g1")
		if len(rp) != 1 || rp[0].Chain != want {
			t.Fatalf("replay %s: %+v", tenant, rp)
		}
		cs, _ := s.ChainsTenant(ctx, tenant)
		if len(cs) != 1 || cs[0] != want {
			t.Fatalf("chains %s: %v", tenant, cs)
		}
		if TenantOfChain(want) != tenant {
			t.Fatal("TenantOfChain disagrees with SQL")
		}
	}
}
