package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/keys"
	"github.com/Celaris-dev1/Ledger/internal/store"
	"github.com/Celaris-dev1/Ledger/internal/storetest"
)

// TestConcurrencyBackupUnderAppends: backups taken while 16 writers append (new chains appear
// mid-backup too) are consistent snapshots: every one loads and verifies, and restores into
// an empty database that verifies afterwards.
func TestConcurrencyBackupUnderAppends(t *testing.T) {
	src := storetest.Open(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	kr, err := anchor.OpenKeyring(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	signer := keys.Ed25519Signer{Key: kr.Active}
	var stop atomic.Bool
	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; !stop.Load(); i++ {
				_, err := src.Append(ctx, store.AppendRequest{Chain: fmt.Sprintf("b%d", (w*7+i)%(4+i/10)), Type: "t",
					ActorChain: []store.Actor{{Kind: "human", ID: "a"}}, Payload: json.RawMessage(fmt.Sprintf(`{"w":%d,"i":%d}`, w, i)),
					IdempotencyKey: fmt.Sprintf("%d-%d", w, i)})
				if err != nil && ctx.Err() == nil {
					t.Error(err)
					return
				}
			}
		}(w)
	}
	var dirs []string
	for i := 0; i < 4; i++ {
		time.Sleep(40 * time.Millisecond)
		dir := filepath.Join(t.TempDir(), "bk")
		m, err := Create(ctx, src, dir, Options{Signer: signer, Keyring: kr})
		if err != nil {
			t.Fatal(err)
		}
		if m.Records == 0 {
			t.Fatal("empty backup")
		}
		dirs = append(dirs, dir)
	}
	stop.Store(true)
	wg.Wait()
	for i, dir := range dirs {
		if _, err := Load(dir, VerifyOptions{Trust: trustOf(kr)}); err != nil {
			t.Fatalf("backup %d taken under load does not verify: %v", i, err)
		}
	}
	dst := storetest.Open(t)
	L, err := Restore(ctx, dst, dirs[len(dirs)-1], VerifyOptions{Trust: trustOf(kr)})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	for name := range L.Chains {
		v, err := dst.Verify(ctx, name)
		if err != nil || !v.OK {
			t.Fatalf("restored %s: %+v %v", name, v, err)
		}
	}
}
