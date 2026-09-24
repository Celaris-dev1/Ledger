package projection

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/testfix"
)

// TestConcurrencyProjectorVsAppendsVsRebuild: the async worker, 8 writers, explicit CatchUp
// calls and 3 full Rebuilds all run at once. Afterwards the stored projection equals the
// in-memory fold (Check) and a fresh rebuild.
func TestConcurrencyProjectorVsAppendsVsRebuild(t *testing.T) {
	s := testStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	p := &PG{Pool: s.Pool, Batch: 5}
	w := NewWorker(p)
	w.Interval = 20 * time.Millisecond
	w.Logf = t.Logf
	wctx, wcancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { w.Run(wctx); close(done) }()

	recs := allFixtureRecords()
	for i := 0; i < 3; i++ { // more volume: replay the fixtures under other chain names
		for _, r := range allFixtureRecords() {
			r.Chain = r.Chain + "-" + string(rune('a'+i))
			recs = append(recs, r)
		}
	}
	var wg sync.WaitGroup
	for k := 0; k < 8; k++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			for j := k; j < len(recs); j += 8 {
				if _, err := s.Append(ctx, testfix.Request(recs[j])); err != nil {
					t.Error(err)
					return
				}
				w.Notify()
			}
		}(k)
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 3; i++ {
			time.Sleep(15 * time.Millisecond)
			if _, err := p.Rebuild(ctx); err != nil {
				t.Error("rebuild:", err)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			if _, err := p.CatchUp(ctx); err != nil {
				t.Error("catch-up:", err)
			}
		}
	}()
	wg.Wait()
	wcancel()
	<-done
	if _, err := p.CatchUp(ctx); err != nil {
		t.Fatal(err)
	}
	if d, err := p.Check(ctx); err != nil || d != "" {
		t.Fatalf("stored projection != fold after concurrent run: %v %s", err, d)
	}
	incr, err := p.Rows(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	rebuilt, _ := p.Rows(ctx, "")
	if d := Diff(incr, rebuilt); d != "" {
		t.Fatalf("concurrent result != rebuild: %s", d)
	}
}
