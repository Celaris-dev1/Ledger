package compliance

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/anchoring"
	"github.com/Celaris-dev1/Ledger/internal/keys"
	"github.com/Celaris-dev1/Ledger/internal/retention"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

// Gatherer collects evidence from a Postgres store.
type Gatherer struct {
	Store   *store.Store
	Anchors *anchoring.Service // optional: re-verify anchor receipts per chain
	Signer  keys.Signer        // optional: include a freshly signed root per chain
	Now     func() time.Time
}

func inWindow(r store.Record, s Scope) bool {
	return (s.From.IsZero() || !r.CreatedAt.Before(s.From)) && (s.To.IsZero() || r.CreatedAt.Before(s.To))
}

// Gather builds the Evidence for scope.
func (g *Gatherer) Gather(ctx context.Context, scope Scope) (*Evidence, error) {
	now := time.Now().UTC()
	if g.Now != nil {
		now = g.Now()
	}
	var recs []store.Record
	var err error
	if scope.GoalID != "" {
		all, err := g.Store.Replay(ctx, scope.GoalID)
		if err != nil {
			return nil, err
		}
		want := map[string]bool{}
		for _, c := range scope.Chains {
			want[c] = true
		}
		seen := map[string]bool{}
		for _, r := range all {
			if len(scope.Chains) > 0 && !want[r.Chain] {
				continue
			}
			if !inWindow(r, scope) {
				continue
			}
			recs = append(recs, r)
			if len(scope.Chains) == 0 && !seen[r.Chain] {
				seen[r.Chain] = true
			}
		}
		if len(scope.Chains) == 0 {
			for c := range seen {
				scope.Chains = append(scope.Chains, c)
			}
			sort.Strings(scope.Chains)
		}
	} else {
		if len(scope.Chains) == 0 {
			if scope.Chains, err = g.Store.Chains(ctx); err != nil {
				return nil, err
			}
		}
		if recs, err = g.Store.WindowRecords(ctx, scope.Chains, scope.From, scope.To); err != nil {
			return nil, err
		}
	}
	ev := &Evidence{Scope: scope, Records: recs, Now: now}
	counts := map[string]int{}
	for _, r := range recs {
		counts[r.Chain]++
	}
	for _, c := range scope.Chains {
		ce := ChainEvidence{Chain: c, RecordsInScope: counts[c]}
		if ce.Verify, err = g.Store.Verify(ctx, c); err != nil {
			return nil, err
		}
		if g.Signer != nil && ce.Verify.OK && ce.Verify.Length > 0 {
			root, err := anchor.SignWith(ctx, g.Signer, c, int64(ce.Verify.Length), ce.Verify.Head)
			if err != nil {
				return nil, err
			}
			ce.Root = &root
		}
		if g.Anchors != nil {
			rep, err := g.Anchors.VerifyChainAnchors(ctx, c)
			if err != nil {
				return nil, err
			}
			ce.Anchors = &rep
		}
		ev.Chains = append(ev.Chains, ce)
	}
	sys, err := g.Store.ChainRecords(ctx, retention.SystemChain)
	if err != nil {
		return nil, err
	}
	ev.Retention = retention.Fold(sys)
	ev.Rotations, ev.RotErrors = rotations(sys)
	return ev, nil
}

// rotations extracts and verifies ledger.key.rotated records; each must also chain from the
// previous rotation's new key (a gap in succession is reported).
func rotations(sys []store.Record) ([]anchor.Rotation, []string) {
	var out []anchor.Rotation
	var errs []string
	for _, r := range sys {
		if r.Type != anchoring.RotationType {
			continue
		}
		var rot anchor.Rotation
		if err := json.Unmarshal(r.Payload, &rot); err != nil {
			errs = append(errs, "undecodable rotation record seq "+itoa(r.Seq))
			continue
		}
		if err := anchor.VerifyRotation(rot); err != nil {
			errs = append(errs, "seq "+itoa(r.Seq)+": "+err.Error())
		}
		if n := len(out); n > 0 && out[n-1].NewKeyID != rot.OldKeyID {
			errs = append(errs, "seq "+itoa(r.Seq)+": rotation from "+rot.OldKeyID+" does not follow the previous new key "+out[n-1].NewKeyID)
		}
		out = append(out, rot)
	}
	return out, errs
}

func itoa(i int64) string { b, _ := json.Marshal(i); return string(b) }

// EvidenceFromRecords builds Evidence from in-memory records (tests, offline packs).
// Chains are verified with store.VerifyRecords; anchors are not checked.
func EvidenceFromRecords(all []store.Record, scope Scope, now time.Time) *Evidence {
	byChain := map[string][]store.Record{}
	var order []string
	for _, r := range all {
		if _, ok := byChain[r.Chain]; !ok {
			order = append(order, r.Chain)
		}
		byChain[r.Chain] = append(byChain[r.Chain], r)
	}
	if len(scope.Chains) == 0 {
		scope.Chains = order
	}
	ev := &Evidence{Scope: scope, Now: now}
	counts := map[string]int{}
	for _, c := range scope.Chains {
		for _, r := range byChain[c] {
			if inWindow(r, scope) && (scope.GoalID == "" || r.GoalID == scope.GoalID) {
				ev.Records = append(ev.Records, r)
				counts[c]++
			}
		}
		ev.Chains = append(ev.Chains, ChainEvidence{Chain: c, Verify: store.VerifyRecords(c, byChain[c]), RecordsInScope: counts[c]})
	}
	sort.SliceStable(ev.Records, func(i, j int) bool { return ev.Records[i].CreatedAt.Before(ev.Records[j].CreatedAt) })
	sys := byChain[retention.SystemChain]
	ev.Retention = retention.Fold(sys)
	ev.Rotations, ev.RotErrors = rotations(sys)
	return ev
}
