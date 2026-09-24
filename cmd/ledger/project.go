package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Celaris-dev1/Ledger/internal/incident"
	"github.com/Celaris-dev1/Ledger/internal/projection"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

func runProject(ctx context.Context, st *store.Store, rebuild, check bool) {
	p := &projection.PG{Pool: st.Pool}
	var stats projection.Stats
	var err error
	if rebuild {
		stats, err = p.Rebuild(ctx)
	} else {
		stats, err = p.CatchUp(ctx)
	}
	if err != nil {
		die("project: %v", err)
	}
	b, _ := json.Marshal(stats)
	fmt.Printf("projected (version %d): %s\n", projection.Version, b)
	if check {
		diff, err := p.Check(ctx)
		if err != nil {
			die("check: %v", err)
		}
		if diff != "" {
			fmt.Printf("CHECK FAILED: stored projection differs from a rebuild:\n%s\n", diff)
			st.Close()
			os.Exit(1)
		}
		fmt.Println("check OK: stored projection == rebuild from records")
	}
}

func runIncident(ctx context.Context, st *store.Store, goal, format, outFile string) {
	if goal == "" {
		die("incident requires --goal")
	}
	rep, err := incident.Build(ctx, st, goal)
	if err != nil {
		die("incident: %v", err)
	}
	if rep == nil {
		die("no records for goal %s", goal)
	}
	var w io.Writer = os.Stdout
	if outFile != "" {
		f, err := os.Create(outFile)
		if err != nil {
			die("%v", err)
		}
		defer f.Close()
		w = f
	}
	switch format {
	case "html":
		err = incident.WriteHTML(w, rep)
	case "md", "markdown":
		err = incident.WriteMarkdown(w, rep)
	case "json":
		err = incident.WriteJSON(w, rep)
	default:
		die("unknown --format %s (json|html|md)", format)
	}
	if err != nil {
		die("%v", err)
	}
	if outFile != "" {
		fmt.Fprintf(os.Stderr, "wrote %s: %s\n", outFile, rep.Summary.Headline)
	}
}
