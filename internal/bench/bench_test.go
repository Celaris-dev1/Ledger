package bench

import (
	"context"
	"os"
	"strconv"
	"testing"
)

// Sizes are small by default so CI stays fast; set LEDGER_BENCH_VERIFY_N=1000000 for the
// 1M-record measurement (see README "Performance").
func envInt(k string, d int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil && v > 0 {
		return v
	}
	return d
}

func scratch(t testing.TB) (context.Context, func()) {
	base := os.Getenv("LEDGER_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("LEDGER_TEST_DATABASE_URL not set")
	}
	return context.Background(), nil
}

func TestAppendAndVerifySmoke(t *testing.T) {
	ctx, _ := scratch(t)
	st, done, err := Scratch(ctx, os.Getenv("LEDGER_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	r, err := Append(ctx, st, 8, 16, 400, 256)
	if err != nil || r.Errors != 0 || !r.AllIntact {
		t.Fatalf("%v %+v", err, r)
	}
	v, err := Verify(ctx, st, 12345, true)
	if err != nil || !v.OK {
		t.Fatalf("%v %+v", err, v)
	}
	t.Log(r)
	t.Log(v)
}

func BenchmarkAppendConcurrent(b *testing.B) {
	ctx, _ := scratch(b)
	st, done, err := Scratch(ctx, os.Getenv("LEDGER_TEST_DATABASE_URL"))
	if err != nil {
		b.Fatal(err)
	}
	defer done()
	n := envInt("LEDGER_BENCH_RECORDS", 2000) // records per iteration
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, err := Append(ctx, st, envInt("LEDGER_BENCH_WRITERS", 16), envInt("LEDGER_BENCH_CHAINS", 64), n, 256)
		if err != nil || r.Errors != 0 {
			b.Fatal(err, r.Errors)
		}
	}
	b.ReportMetric(float64(n*b.N)/b.Elapsed().Seconds(), "records/s")
}

func BenchmarkVerifyLongChain(b *testing.B) {
	ctx, _ := scratch(b)
	st, done, err := Scratch(ctx, os.Getenv("LEDGER_TEST_DATABASE_URL"))
	if err != nil {
		b.Fatal(err)
	}
	defer done()
	n := envInt("LEDGER_BENCH_VERIFY_N", 50000)
	if err := BulkLoad(ctx, st, "long", n); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v, err := st.Verify(ctx, "long")
		if err != nil || !v.OK {
			b.Fatal(err, v)
		}
	}
	b.ReportMetric(float64(n*b.N)/b.Elapsed().Seconds(), "records/s")
}
