package featureflags

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/db"
)

// Row is one persisted flag value.
type Row struct {
	FlagKey   string
	Scope     Scope
	ScopeKey  string
	Value     bool
	UpdatedBy string
	UpdatedAt time.Time
}

// Store is the PostgreSQL projection of runtime feature flags.
type Store struct{}

// NewStore builds a Store.
func NewStore() *Store { return &Store{} }

// Get returns the row for (key, scope, scopeKey), or nil when absent.
func (s *Store) Get(ctx context.Context, q db.Querier, key string, scope Scope, scopeKey string) (*Row, error) {
	const sql = `SELECT flag_key, scope, scope_key, value, updated_by, updated_at
	             FROM feature_flags
	             WHERE flag_key = $1 AND scope = $2 AND scope_key = $3`
	var r Row
	err := q.QueryRow(ctx, sql, key, string(scope), scopeKey).
		Scan(&r.FlagKey, (*string)(&r.Scope), &r.ScopeKey, &r.Value, &r.UpdatedBy, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// Upsert writes (or overwrites) a flag value.
func (s *Store) Upsert(ctx context.Context, q db.Querier, r Row) error {
	const sql = `INSERT INTO feature_flags (flag_key, scope, scope_key, value, updated_by)
	             VALUES ($1,$2,$3,$4,$5)
	             ON CONFLICT (flag_key, scope, scope_key) DO UPDATE SET
	               value = EXCLUDED.value,
	               updated_by = EXCLUDED.updated_by,
	               updated_at = now()`
	_, err := q.Exec(ctx, sql, r.FlagKey, string(r.Scope), r.ScopeKey, r.Value, r.UpdatedBy)
	return err
}

// Delete removes a flag value (revert to the wider scope / built-in
// default). Reports whether a row existed.
func (s *Store) Delete(ctx context.Context, q db.Querier, key string, scope Scope, scopeKey string) (bool, error) {
	const sql = `DELETE FROM feature_flags WHERE flag_key = $1 AND scope = $2 AND scope_key = $3`
	tag, err := q.Exec(ctx, sql, key, string(scope), scopeKey)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// List returns every persisted row for a flag key, platform row first then
// cluster overrides ordered by scope_key.
func (s *Store) List(ctx context.Context, q db.Querier, key string) ([]Row, error) {
	const sql = `SELECT flag_key, scope, scope_key, value, updated_by, updated_at
	             FROM feature_flags WHERE flag_key = $1
	             ORDER BY scope DESC, scope_key`
	rows, err := q.Query(ctx, sql, key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Row
	for rows.Next() {
		var r Row
		if err := rows.Scan(&r.FlagKey, (*string)(&r.Scope), &r.ScopeKey, &r.Value, &r.UpdatedBy, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
