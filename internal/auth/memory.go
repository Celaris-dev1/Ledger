package auth

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

// Memory is an in-memory Store (tests, and ledgerd without a database for auth).
type Memory struct {
	mu       sync.Mutex
	tokens   map[string]*Token
	users    map[string]*User
	sessions map[string]*Session
}

// NewMemory returns an empty store.
func NewMemory() *Memory {
	return &Memory{tokens: map[string]*Token{}, users: map[string]*User{}, sessions: map[string]*Session{}}
}

func (m *Memory) InsertToken(_ context.Context, t Token) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[t.ID] = &t
	return nil
}

func (m *Memory) TokenByHash(_ context.Context, hash string) (*Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tokens {
		if t.Hash == hash {
			c := *t
			return &c, nil
		}
	}
	return nil, nil
}

func (m *Memory) TokenByID(_ context.Context, id string) (*Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[id]
	if !ok {
		return nil, ErrNotFound
	}
	c := *t
	return &c, nil
}

func (m *Memory) ListTokens(context.Context) ([]Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Token{}
	for _, t := range m.tokens {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt) || out[i].CreatedAt.Equal(out[j].CreatedAt) && out[i].ID < out[j].ID
	})
	return out, nil
}

func (m *Memory) RevokeToken(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[id]
	if !ok {
		return ErrNotFound
	}
	if t.RevokedAt == nil {
		now := time.Now().UTC()
		t.RevokedAt = &now
	}
	return nil
}

func (m *Memory) TouchToken(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.tokens[id]; ok {
		t.LastUsed = &at
	}
	return nil
}

func (m *Memory) CountActiveTokens(context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, t := range m.tokens {
		if t.RevokedAt == nil {
			n++
		}
	}
	return n, nil
}

func (m *Memory) UpsertOIDCUser(_ context.Context, issuer, subject, email, name, role string, force bool) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.Issuer == issuer && u.Subject == subject {
			u.Email, u.Name = email, name
			if force {
				u.Role = role
			}
			c := *u
			return &c, nil
		}
	}
	u := &User{ID: "usr_" + RandToken(9), Issuer: issuer, Subject: subject, Email: strings.ToLower(email), Name: name, Role: role, CreatedAt: time.Now().UTC()}
	m.users[u.ID] = u
	c := *u
	return &c, nil
}

func (m *Memory) UserByID(_ context.Context, id string) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return nil, ErrNotFound
	}
	c := *u
	return &c, nil
}

func (m *Memory) ListUsers(context.Context) ([]User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []User{}
	for _, u := range m.users {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out, nil
}

func (m *Memory) SetUserRole(_ context.Context, id, role string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return ErrNotFound
	}
	u.Role = role
	return nil
}

func (m *Memory) SetUserDisabled(_ context.Context, id string, d bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return ErrNotFound
	}
	u.Disabled = d
	return nil
}

func (m *Memory) InsertSession(_ context.Context, s Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.Hash] = &s
	return nil
}

func (m *Memory) SessionByHash(_ context.Context, hash string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[hash]
	if !ok {
		return nil, nil
	}
	c := *s
	return &c, nil
}

func (m *Memory) DeleteSession(_ context.Context, hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, hash)
	return nil
}
