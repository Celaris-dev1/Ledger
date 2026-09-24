package web

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/auth"
	"github.com/Celaris-dev1/Ledger/internal/store"
	"github.com/jackc/pgx/v5"
)

func pgWebStore(t *testing.T) *store.Store {
	base := os.Getenv("LEDGER_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("LEDGER_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	schema := "ledger_web_test_" + auth.HashSecret(auth.RandToken(8))[:10]
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(base)
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	st, err := store.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		st.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		admin.Close(context.Background())
	})
	return st
}

// TestConcurrencySSESubscribersUnderLoad: 16 SSE clients repeatedly join, read a few events
// and leave (resuming with Last-Event-ID) while 8 writers append to 4 chains. Every client
// ends with every record exactly once, in seq order per chain, and no subscription leaks.
func TestConcurrencySSESubscribersUnderLoad(t *testing.T) {
	st := pgWebStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	hub := NewHub()
	lctx, lcancel := context.WithCancel(ctx)
	defer lcancel()
	go Listen(lctx, st.Pool, hub, nil)
	srv := httptest.NewServer(&Streamer{Src: &PGStream{Pool: st.Pool}, Hub: hub, Poll: 100 * time.Millisecond, Heartbeat: time.Second, Batch: 7})
	defer srv.Close()

	const chains, perWriter, writers = 4, 25, 8
	total := writers * perWriter
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				_, err := st.Append(ctx, store.AppendRequest{Chain: fmt.Sprintf("s%d", (w+i)%chains), Type: "t",
					ActorChain: []store.Actor{{Kind: "human", ID: "a"}}, Payload: json.RawMessage(fmt.Sprintf(`{"w":%d,"i":%d}`, w, i))})
				if err != nil {
					t.Error(err)
					return
				}
				hub.Kick()
				if i%5 == 0 {
					time.Sleep(time.Millisecond)
				}
			}
		}(w)
	}
	results := make([]map[string][]int64, 16)
	for c := range results {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			seen := map[string][]int64{}
			last, n := "", 0
			for n < total && ctx.Err() == nil {
				rctx, rcancel := context.WithCancel(ctx)
				path := srv.URL + "/?from=start"
				req, _ := http.NewRequestWithContext(rctx, "GET", path, nil)
				if last != "" {
					req.Header.Set("Last-Event-ID", last)
				}
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					rcancel()
					t.Error(err)
					return
				}
				br := bufio.NewReader(resp.Body)
				want := 1 + (c+n)%9 // leave after a few events
				got := 0
				var ev sseEvent
				for got < want && n < total {
					line, err := br.ReadString('\n')
					if err != nil {
						break
					}
					switch {
					case line == "\n":
						if ev.event == "record" {
							var r store.Record
							if err := json.Unmarshal([]byte(ev.data), &r); err != nil {
								t.Error(err)
							}
							seen[r.Chain] = append(seen[r.Chain], r.Seq)
							last, n, got = ev.id, n+1, got+1
						}
						ev = sseEvent{}
					case len(line) > 4 && line[:4] == "id: ":
						ev.id = line[4 : len(line)-1]
					case len(line) > 7 && line[:7] == "event: ":
						ev.event = line[7 : len(line)-1]
					case len(line) > 6 && line[:6] == "data: ":
						ev.data = line[6 : len(line)-1]
					}
				}
				rcancel()
				resp.Body.Close()
			}
			results[c] = seen
		}(c)
	}
	wg.Wait()
	for c, seen := range results {
		sum := 0
		for ch, seqs := range seen {
			for i, s := range seqs {
				if s != int64(i+1) {
					t.Fatalf("client %d chain %s: got seqs %v (gap or duplicate)", c, ch, seqs)
				}
			}
			sum += len(seqs)
		}
		if sum != total {
			t.Fatalf("client %d saw %d records, want %d", c, sum, total)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for hub.Subscribers() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d hub subscriptions leaked", hub.Subscribers())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
