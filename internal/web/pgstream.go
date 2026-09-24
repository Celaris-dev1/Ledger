package web

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PGStream is the Postgres StreamSource: one indexed range scan per chain from its cursor.
type PGStream struct{ Pool *pgxpool.Pool }

func (p *PGStream) Heads(ctx context.Context) (map[string]int64, error) {
	rows, err := p.Pool.Query(ctx, `SELECT name, head_seq FROM chains`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var n string
		var s int64
		if err := rows.Scan(&n, &s); err != nil {
			return nil, err
		}
		out[n] = s
	}
	return out, rows.Err()
}

func (p *PGStream) Since(ctx context.Context, cursor map[string]int64, chain, goal string, limit int) (map[string][]store.Record, error) {
	names := make([]string, 0, len(cursor))
	seqs := make([]int64, 0, len(cursor))
	for c, s := range cursor {
		names = append(names, c)
		seqs = append(seqs, s)
	}
	rows, err := p.Pool.Query(ctx, `
		SELECT r.id::text, r.chain, r.seq, r.type, COALESCE(r.goal_id,''), r.actor_chain::text, COALESCE(r.policy_version,''),
		       r.payload::text, r.created_at, r.prev_hash, r.hash, COALESCE(r.idempotency_key,'')
		FROM chains c
		LEFT JOIN unnest($1::text[], $2::bigint[]) AS cur(chain, seq) ON cur.chain = c.name
		CROSS JOIN LATERAL (
			SELECT * FROM records r
			WHERE r.chain = c.name AND r.seq > COALESCE(cur.seq, 0) AND ($4 = '' OR r.goal_id = $4)
			ORDER BY r.seq LIMIT $5
		) r
		WHERE ($3 = '' OR c.name = $3) AND c.head_seq > COALESCE(cur.seq, 0)
		ORDER BY r.chain, r.seq`, names, seqs, chain, goal, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]store.Record{}
	for rows.Next() {
		var r store.Record
		var ac, pl string
		if err := rows.Scan(&r.ID, &r.Chain, &r.Seq, &r.Type, &r.GoalID, &ac, &r.PolicyVersion, &pl, &r.CreatedAt, &r.PrevHash, &r.Hash, &r.IdempotencyKey); err != nil {
			return nil, err
		}
		r.CreatedAt = r.CreatedAt.UTC()
		r.ActorChain, r.Payload = json.RawMessage(ac), json.RawMessage(pl)
		out[r.Chain] = append(out[r.Chain], r)
	}
	return out, rows.Err()
}

// Listen turns Postgres NOTIFY ledger_records (migration 0300 trigger) into hub wake-ups,
// reconnecting with backoff until ctx ends. Streams keep polling if this is down.
func Listen(ctx context.Context, pool *pgxpool.Pool, hub *Hub, lg *log.Logger) {
	backoff := time.Second
	for ctx.Err() == nil {
		err := func() error {
			conn, err := pool.Acquire(ctx)
			if err != nil {
				return err
			}
			defer conn.Release()
			if _, err := conn.Exec(ctx, `LISTEN ledger_records`); err != nil {
				return err
			}
			backoff = time.Second
			for {
				if _, err := conn.Conn().WaitForNotification(ctx); err != nil {
					// the connection state is unknown after an error: do not return it to the pool
					_ = conn.Conn().Close(context.Background())
					return err
				}
				hub.Kick()
			}
		}()
		if ctx.Err() != nil {
			return
		}
		if lg != nil {
			lg.Printf("ledgerd: stream listener: %v (polling continues; retrying in %s)", err, backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}
