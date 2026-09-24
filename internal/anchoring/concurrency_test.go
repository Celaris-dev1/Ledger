package anchoring

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

// TestConcurrencySchedulerVsAppendsVsRotation: the anchoring scheduler ticks while 16 writers
// append to 4 chains and the root key is rotated 5 times. Every stored receipt must verify
// (root trusted via the keyring + recorded rotations, RFC 3161 token valid, head on chain).
func TestConcurrencySchedulerVsAppendsVsRotation(t *testing.T) {
	st := testStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ca, _, tb := fakeTSAs(t, 1)
	kr, err := anchor.OpenKeyring(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{Store: st, Key: kr.Active, Keyring: kr, Verifier: Verifier{TSARoots: ca.Pool()},
		Backends: []Backend{tb, &FileBackend{Dir: t.TempDir()}}}
	sched := &Scheduler{Svc: svc, EveryN: 1}
	chains := []string{"a", "b", "c", "d"}
	for _, c := range chains {
		appendN(t, st, c, 1, 1)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 15; i++ {
				time.Sleep(3 * time.Millisecond) // keep appending while keys rotate
				_, err := st.Append(ctx, store.AppendRequest{Chain: chains[(w+i)%4], Type: "gate.run.enforced",
					ActorChain: []store.Actor{{Kind: "human", ID: "h"}}, Payload: json.RawMessage(fmt.Sprintf(`{"w":%d,"i":%d}`, w, i))})
				if err != nil {
					t.Error(err)
					return
				}
			}
		}(w)
	}
	var tickWG sync.WaitGroup
	tickWG.Add(1)
	go func() {
		defer tickWG.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := sched.Tick(ctx); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	wg.Add(1)
	go func() { // rotations race the scheduler's signing
		defer wg.Done()
		for r := 0; r < 5; r++ {
			time.Sleep(10 * time.Millisecond)
			if _, _, err := svc.RotateKey(ctx, "ops", true); err != nil {
				t.Error(err)
			}
		}
	}()
	wg.Wait()
	close(stop)
	tickWG.Wait()
	sched.EveryN = 1
	if _, err := sched.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	for _, c := range chains {
		rep, err := svc.VerifyChainAnchors(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		if !rep.OK || len(rep.Checks) == 0 {
			t.Fatalf("chain %s: %s", c, FormatReport(rep))
		}
	}
}
