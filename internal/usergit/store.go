// PostgreSQL projection of user git connections (W4). Uses the W3
// user_git_connections table (migration 0028) keyed (org_id, user_sub,
// provider). Every statement filters org_id + user_sub: tenant and user
// isolation is enforced at SQL level. Only the EncryptedRow methods ever
// touch token columns; ListByUser selects metadata only.
package usergit

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/db"
)

// ErrNotFound: no connection row for (org, user, provider).
var ErrNotFound = errors.New("usergit: connection not found")

// Connection is the metadata view of a user git connection. It never
// carries token material and is safe to return over REST.
type Connection struct {
	ID            string     `json:"id"`
	OrgID         string     `json:"orgId"`
	UserSub       string     `json:"-"`
	Provider      string     `json:"provider"`
	ProviderLogin string     `json:"providerLogin"`
	Scopes        string     `json:"scopes"`
	APIBase       string     `json:"apiBase,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	LastUsedAt    *time.Time `json:"lastUsedAt,omitempty"`
}

// EncryptedRow is a Connection plus its envelope-encrypted refresh token.
// Only the Service sees the plaintext.
type EncryptedRow struct {
	Connection
	RefreshTokenEnc []byte
	DEKEnc          []byte
}

// Store is the PostgreSQL projection of user git connection state.
type Store struct{}

func NewStore() *Store { return &Store{} }

const connCols = `id, org_id, user_sub, provider, provider_login, scopes, api_base, created_at, last_used_at`

func scanConnection(row interface{ Scan(...any) error }) (*Connection, error) {
	var c Connection
	err := row.Scan(&c.ID, &c.OrgID, &c.UserSub, &c.Provider, &c.ProviderLogin,
		&c.Scopes, &c.APIBase, &c.CreatedAt, &c.LastUsedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// UpsertEncrypted inserts the row or, on (org_id, user_sub, provider)
// conflict, replaces it wholesale — including the primary key, since the
// ciphertext AAD is bound to the fresh row ID. No other table references
// user_git_connections, so replacing the PK is safe.
func (s *Store) UpsertEncrypted(ctx context.Context, q db.Querier, r *EncryptedRow) error {
	const sql = `INSERT INTO user_git_connections
		(id, org_id, user_sub, provider, provider_login, scopes, refresh_token_enc, dek_enc, api_base)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (org_id, user_sub, provider) DO UPDATE SET
		id = EXCLUDED.id,
		provider_login = EXCLUDED.provider_login,
		scopes = EXCLUDED.scopes,
		refresh_token_enc = EXCLUDED.refresh_token_enc,
		dek_enc = EXCLUDED.dek_enc,
		api_base = EXCLUDED.api_base,
		last_used_at = NULL
		RETURNING ` + connCols
	out, err := scanConnection(q.QueryRow(ctx, sql,
		r.ID, r.OrgID, r.UserSub, r.Provider, r.ProviderLogin, r.Scopes,
		r.RefreshTokenEnc, r.DEKEnc, r.APIBase))
	if err != nil {
		return err
	}
	r.Connection = *out
	return nil
}

// GetEncrypted loads the row including ciphertext for (org, user, provider).
func (s *Store) GetEncrypted(ctx context.Context, q db.Querier, orgID, userSub, provider string) (*EncryptedRow, error) {
	const sql = `SELECT ` + connCols + `, refresh_token_enc, dek_enc
		FROM user_git_connections
		WHERE org_id = $1 AND user_sub = $2 AND provider = $3`
	var r EncryptedRow
	err := q.QueryRow(ctx, sql, orgID, userSub, provider).Scan(
		&r.ID, &r.OrgID, &r.UserSub, &r.Provider, &r.ProviderLogin,
		&r.Scopes, &r.APIBase, &r.CreatedAt, &r.LastUsedAt,
		&r.RefreshTokenEnc, &r.DEKEnc)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ListByUser returns metadata for every connection of (org, user); token
// columns are never selected.
func (s *Store) ListByUser(ctx context.Context, q db.Querier, orgID, userSub string) ([]Connection, error) {
	const sql = `SELECT ` + connCols + ` FROM user_git_connections
		WHERE org_id = $1 AND user_sub = $2 ORDER BY provider`
	rows, err := q.Query(ctx, sql, orgID, userSub)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Connection{}
	for rows.Next() {
		c, err := scanConnection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// Delete removes the row for (org, user, provider); ErrNotFound when absent.
func (s *Store) Delete(ctx context.Context, q db.Querier, orgID, userSub, provider string) error {
	const sql = `DELETE FROM user_git_connections
		WHERE org_id = $1 AND user_sub = $2 AND provider = $3`
	tag, err := q.Exec(ctx, sql, orgID, userSub, provider)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateRefreshToken replaces the encrypted refresh token of a row (rotation).
func (s *Store) UpdateRefreshToken(ctx context.Context, q db.Querier, id string, refreshEnc, dekEnc []byte) error {
	const sql = `UPDATE user_git_connections SET refresh_token_enc = $2, dek_enc = $3 WHERE id = $1`
	tag, err := q.Exec(ctx, sql, id, refreshEnc, dekEnc)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchLastUsed stamps last_used_at = now() for the row (best-effort).
func (s *Store) TouchLastUsed(ctx context.Context, q db.Querier, id string) error {
	const sql = `UPDATE user_git_connections SET last_used_at = now() WHERE id = $1`
	_, err := q.Exec(ctx, sql, id)
	return err
}
