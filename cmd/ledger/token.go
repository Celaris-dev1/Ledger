package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/auth"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

// runToken implements `ledger token create|list|revoke` (operator bootstrap of API tokens;
// admins can also manage them in the web UI under /admin).
func runToken(ctx context.Context, st *store.Store, sub, name, role string, rest []string) {
	ts := &auth.PG{Pool: st.Pool}
	switch sub {
	case "create":
		by := "cli:" + env("USER", "operator")
		plain, t, err := auth.NewToken(ctx, ts, name, role, by)
		if err != nil {
			die("token create: %v", err)
		}
		fmt.Fprintf(os.Stderr, "created %s token %s (%s); store it now, it is not shown again:\n", t.Role, t.ID, t.Name)
		fmt.Println(plain)
	case "list":
		toks, err := ts.ListTokens(ctx)
		if err != nil {
			die("token list: %v", err)
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tROLE\tPREFIX\tCREATED\tLAST USED\tSTATUS")
		for _, t := range toks {
			last, status := "never", "active"
			if t.LastUsed != nil {
				last = t.LastUsed.UTC().Format(time.RFC3339)
			}
			if t.RevokedAt != nil {
				status = "revoked " + t.RevokedAt.UTC().Format(time.RFC3339)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s…\t%s\t%s\t%s\n", t.ID, t.Name, t.Role, t.Prefix, t.CreatedAt.UTC().Format(time.RFC3339), last, status)
		}
		_ = tw.Flush()
	case "revoke":
		if len(rest) != 1 {
			die("token revoke requires exactly one token id")
		}
		if err := ts.RevokeToken(ctx, rest[0]); err != nil {
			die("token revoke: %v", err)
		}
		fmt.Printf("revoked %s\n", rest[0])
	default:
		die("token requires create|list|revoke")
	}
}
