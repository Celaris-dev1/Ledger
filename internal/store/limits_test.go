package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func okReq() AppendRequest {
	return AppendRequest{Chain: "c", Type: "t", ActorChain: []Actor{{Kind: "human", ID: "alice"}}, Payload: json.RawMessage(`{"x":1}`)}
}

// Regression (hardening): inputs Postgres cannot store (NUL in text columns, keys larger
// than a btree index entry) used to surface as 500s from the database; they are client errors.
func TestAppendRejectsUnstorableInput(t *testing.T) {
	big := strings.Repeat("k", 4000)
	cases := map[string]func(r *AppendRequest){
		"nul chain":    func(r *AppendRequest) { r.Chain = "c\x00" },
		"nul type":     func(r *AppendRequest) { r.Type = "t\x00x" },
		"nul goal":     func(r *AppendRequest) { r.GoalID = "\x00" },
		"nul policy":   func(r *AppendRequest) { r.PolicyVersion = "\x00" },
		"nul idem key": func(r *AppendRequest) { r.IdempotencyKey = "\x00" },
		"nul actor id": func(r *AppendRequest) { r.ActorChain[0].ID = "a\x00" },
		"nul actor model": func(r *AppendRequest) {
			r.ActorChain = append(r.ActorChain, Actor{Kind: "agent", ID: "b", Model: "\x00"})
		},
		"huge chain":       func(r *AppendRequest) { r.Chain = big },
		"huge idem key":    func(r *AppendRequest) { r.IdempotencyKey = big },
		"huge goal":        func(r *AppendRequest) { r.GoalID = big },
		"huge actor id":    func(r *AppendRequest) { r.ActorChain[0].ID = big },
		"array payload":    func(r *AppendRequest) { r.Payload = json.RawMessage(`[1]`) },
		"string payload":   func(r *AppendRequest) { r.Payload = json.RawMessage(`"x"`) },
		"number payload":   func(r *AppendRequest) { r.Payload = json.RawMessage(`5`) },
		"trailing payload": func(r *AppendRequest) { r.Payload = json.RawMessage(`{} {"hidden":1}`) },
		"too many actors":  func(r *AppendRequest) { r.ActorChain = append(r.ActorChain, make([]Actor, MaxActors)...) },
	}
	for name, mut := range cases {
		r := okReq()
		mut(&r)
		var ve *ValidationError
		if err := r.Validate(); !errors.As(err, &ve) {
			t.Errorf("%s: want ValidationError, got %v", name, err)
		}
	}
	r := okReq()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	s := testStore(t)
	for name, mut := range cases {
		r := okReq()
		mut(&r)
		var ve *ValidationError
		if _, err := s.Append(context.Background(), r); !errors.As(err, &ve) {
			t.Errorf("store %s: want ValidationError, got %v", name, err)
		}
	}
	// limits are inclusive: the maximum sizes are storable
	r = okReq()
	r.Chain, r.IdempotencyKey, r.GoalID = strings.Repeat("c", MaxNameLen), strings.Repeat("k", MaxNameLen), strings.Repeat("g", MaxNameLen)
	r.ActorChain[0].ID = strings.Repeat("a", MaxNameLen)
	if _, err := s.Append(context.Background(), r); err != nil {
		t.Fatalf("max-size append: %v", err)
	}
}
