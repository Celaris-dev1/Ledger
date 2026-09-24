// Package auth implements access control for the Ledger API and web UI: roles, API tokens
// hashed at rest, OIDC single sign-on (authorization code + PKCE), cookie sessions and CSRF.
//
// Roles and what they may do:
//
//	admin    everything, including token and user management
//	auditor  read everything (UI, projections, stream, anchors) and export
//	viewer   read everything, no export
//	writer   append records plus the contract reads agents use (records, verify, replay, root);
//	         no UI, no export. The legacy LEDGER_TOKEN is a writer.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// Role names.
const (
	RoleAdmin   = "admin"
	RoleAuditor = "auditor"
	RoleViewer  = "viewer"
	RoleWriter  = "writer"
)

// Perm is a permission checked by a route.
type Perm string

const (
	PermAppend Perm = "append" // POST /v1/records
	PermRead   Perm = "read"   // contract reads: records, verify, replay, root
	PermView   Perm = "view"   // UI pages, projections, incidents, anchors, stream
	PermExport Perm = "export" // auditor packs, incident downloads
	PermAdmin  Perm = "admin"  // token and user management
)

var rolePerms = map[string][]Perm{
	RoleAdmin:   {PermAppend, PermRead, PermView, PermExport, PermAdmin},
	RoleAuditor: {PermRead, PermView, PermExport},
	RoleViewer:  {PermRead, PermView},
	RoleWriter:  {PermAppend, PermRead},
}

// Roles lists the valid roles, most privileged first.
var Roles = []string{RoleAdmin, RoleAuditor, RoleViewer, RoleWriter}

// ValidRole reports whether r is a known role.
func ValidRole(r string) bool { _, ok := rolePerms[r]; return ok }

// Can reports whether role has perm.
func Can(role string, p Perm) bool {
	for _, q := range rolePerms[role] {
		if q == p {
			return true
		}
	}
	return false
}

// Principal is the authenticated caller of a request.
type Principal struct {
	Kind  string `json:"kind"` // user | token | legacy | anonymous
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
	Role  string `json:"role"`
	// Session is set when the request was authenticated by a session cookie.
	Session *Session `json:"-"`
}

// Can reports whether the principal has perm.
func (p *Principal) Can(perm Perm) bool { return p != nil && Can(p.Role, perm) }

// Label is a short display name.
func (p *Principal) Label() string {
	if p == nil {
		return ""
	}
	if p.Email != "" {
		return p.Email
	}
	if p.Name != "" {
		return p.Name
	}
	return p.ID
}

type ctxKey struct{}

// WithPrincipal stores p in ctx.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext returns the request principal (nil if unauthenticated).
func FromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKey{}).(*Principal)
	return p
}

// Token is a stored API token (only its SHA-256 is kept).
type Token struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Role      string     `json:"role"`
	Prefix    string     `json:"prefix"` // first characters of the plaintext, for recognition
	Hash      string     `json:"-"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	LastUsed  *time.Time `json:"last_used_at,omitempty"`
}

// User is an SSO user.
type User struct {
	ID        string    `json:"id"`
	Issuer    string    `json:"issuer"`
	Subject   string    `json:"subject"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	Disabled  bool      `json:"disabled"`
	CreatedAt time.Time `json:"created_at"`
}

// Session is a browser session (only the SHA-256 of the cookie value is stored).
type Session struct {
	Hash      string    `json:"-"`
	Kind      string    `json:"kind"` // user | token
	SubjectID string    `json:"subject_id"`
	CSRF      string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ErrNotFound is returned for unknown ids.
var ErrNotFound = errors.New("not found")

// Store persists tokens, users and sessions.
type Store interface {
	InsertToken(ctx context.Context, t Token) error
	TokenByHash(ctx context.Context, hash string) (*Token, error) // nil,nil when unknown
	TokenByID(ctx context.Context, id string) (*Token, error)
	ListTokens(ctx context.Context) ([]Token, error)
	RevokeToken(ctx context.Context, id string) error
	TouchToken(ctx context.Context, id string, at time.Time) error
	CountActiveTokens(ctx context.Context) (int, error)

	UpsertOIDCUser(ctx context.Context, issuer, subject, email, name, role string, forceRole bool) (*User, error)
	UserByID(ctx context.Context, id string) (*User, error)
	ListUsers(ctx context.Context) ([]User, error)
	SetUserRole(ctx context.Context, id, role string) error
	SetUserDisabled(ctx context.Context, id string, disabled bool) error

	InsertSession(ctx context.Context, s Session) error
	SessionByHash(ctx context.Context, hash string) (*Session, error)
	DeleteSession(ctx context.Context, hash string) error
}

// RandToken returns n random bytes, base64url encoded.
func RandToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// HashSecret is the at-rest form of a token or session id.
func HashSecret(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// TokenPrefix marks Ledger API tokens.
const TokenPrefix = "ldg_"

// NewToken creates and stores a token; the plaintext is returned once and never stored.
func NewToken(ctx context.Context, st Store, name, role, createdBy string) (string, *Token, error) {
	if !ValidRole(role) {
		return "", nil, errors.New("unknown role " + role)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil, errors.New("token name is required")
	}
	plain := TokenPrefix + RandToken(32)
	t := Token{ID: "tok_" + RandToken(9), Name: name, Role: role, Prefix: plain[:10], Hash: HashSecret(plain), CreatedBy: createdBy, CreatedAt: time.Now().UTC()}
	if err := st.InsertToken(ctx, t); err != nil {
		return "", nil, err
	}
	return plain, &t, nil
}
