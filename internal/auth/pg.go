package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PG is the Postgres Store (tables from migration 0300_ui_auth.sql).
type PG struct{ Pool *pgxpool.Pool }

const tokenCols = `id, name, role, prefix, token_hash, created_by, created_at, revoked_at, last_used_at`

func scanToken(row pgx.Row) (*Token, error) {
	var t Token
	err := row.Scan(&t.ID, &t.Name, &t.Role, &t.Prefix, &t.Hash, &t.CreatedBy, &t.CreatedAt, &t.RevokedAt, &t.LastUsed)
	if err != nil {
		return nil, err
	}
	t.CreatedAt = t.CreatedAt.UTC()
	return &t, nil
}

func (p *PG) InsertToken(ctx context.Context, t Token) error {
	_, err := p.Pool.Exec(ctx, `INSERT INTO auth_tokens(id,name,role,prefix,token_hash,created_by,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		t.ID, t.Name, t.Role, t.Prefix, t.Hash, t.CreatedBy, t.CreatedAt)
	return err
}

func (p *PG) TokenByHash(ctx context.Context, hash string) (*Token, error) {
	t, err := scanToken(p.Pool.QueryRow(ctx, `SELECT `+tokenCols+` FROM auth_tokens WHERE token_hash=$1`, hash))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

func (p *PG) TokenByID(ctx context.Context, id string) (*Token, error) {
	t, err := scanToken(p.Pool.QueryRow(ctx, `SELECT `+tokenCols+` FROM auth_tokens WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

func (p *PG) ListTokens(ctx context.Context) ([]Token, error) {
	rows, err := p.Pool.Query(ctx, `SELECT `+tokenCols+` FROM auth_tokens ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Token{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

func (p *PG) RevokeToken(ctx context.Context, id string) error {
	tag, err := p.Pool.Exec(ctx, `UPDATE auth_tokens SET revoked_at=COALESCE(revoked_at, now()) WHERE id=$1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (p *PG) TouchToken(ctx context.Context, id string, at time.Time) error {
	_, err := p.Pool.Exec(ctx, `UPDATE auth_tokens SET last_used_at=$2 WHERE id=$1`, id, at)
	return err
}

func (p *PG) CountActiveTokens(ctx context.Context) (int, error) {
	var n int
	err := p.Pool.QueryRow(ctx, `SELECT count(*) FROM auth_tokens WHERE revoked_at IS NULL`).Scan(&n)
	return n, err
}

const userCols = `id, issuer, subject, email, name, role, disabled, created_at`

func scanUser(row pgx.Row) (*User, error) {
	var u User
	if err := row.Scan(&u.ID, &u.Issuer, &u.Subject, &u.Email, &u.Name, &u.Role, &u.Disabled, &u.CreatedAt); err != nil {
		return nil, err
	}
	u.CreatedAt = u.CreatedAt.UTC()
	return &u, nil
}

func (p *PG) UpsertOIDCUser(ctx context.Context, issuer, subject, email, name, role string, force bool) (*User, error) {
	return scanUser(p.Pool.QueryRow(ctx, `INSERT INTO auth_users(id,issuer,subject,email,name,role) VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (issuer, subject) DO UPDATE SET email=EXCLUDED.email, name=EXCLUDED.name,
			role=CASE WHEN $7 THEN EXCLUDED.role ELSE auth_users.role END
		RETURNING `+userCols, "usr_"+RandToken(9), issuer, subject, strings.ToLower(email), name, role, force))
}

func (p *PG) UserByID(ctx context.Context, id string) (*User, error) {
	u, err := scanUser(p.Pool.QueryRow(ctx, `SELECT `+userCols+` FROM auth_users WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

func (p *PG) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := p.Pool.Query(ctx, `SELECT `+userCols+` FROM auth_users ORDER BY email, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func (p *PG) SetUserRole(ctx context.Context, id, role string) error {
	tag, err := p.Pool.Exec(ctx, `UPDATE auth_users SET role=$2 WHERE id=$1`, id, role)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (p *PG) SetUserDisabled(ctx context.Context, id string, d bool) error {
	tag, err := p.Pool.Exec(ctx, `UPDATE auth_users SET disabled=$2 WHERE id=$1`, id, d)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (p *PG) InsertSession(ctx context.Context, s Session) error {
	// opportunistic cleanup keeps the table bounded
	_, _ = p.Pool.Exec(ctx, `DELETE FROM auth_sessions WHERE expires_at < now() - interval '1 day'`)
	_, err := p.Pool.Exec(ctx, `INSERT INTO auth_sessions(session_hash,kind,subject_id,csrf,created_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6)`,
		s.Hash, s.Kind, s.SubjectID, s.CSRF, s.CreatedAt, s.ExpiresAt)
	return err
}

func (p *PG) SessionByHash(ctx context.Context, hash string) (*Session, error) {
	var s Session
	err := p.Pool.QueryRow(ctx, `SELECT session_hash,kind,subject_id,csrf,created_at,expires_at FROM auth_sessions WHERE session_hash=$1`, hash).
		Scan(&s.Hash, &s.Kind, &s.SubjectID, &s.CSRF, &s.CreatedAt, &s.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &s, err
}

func (p *PG) DeleteSession(ctx context.Context, hash string) error {
	_, err := p.Pool.Exec(ctx, `DELETE FROM auth_sessions WHERE session_hash=$1`, hash)
	return err
}
