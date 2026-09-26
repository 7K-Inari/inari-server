package leaderlease

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// pgStore implements the store seam against the leader_leases table. All
// expiry math runs on the DB clock (now()) so replicas need no clock-skew
// handling.
type pgStore struct {
	pool *pgxpool.Pool
}

func (s *pgStore) acquire(ctx context.Context, name, holder string, ttl time.Duration) (bool, error) {
	// Take the row when it is free or its previous holder's lease expired
	// (pod death without Release). The conflict-update's WHERE is what makes
	// concurrent acquirers safe: exactly one wins.
	const sql = `INSERT INTO leader_leases (name, holder, expires_at)
	             VALUES ($1, $2, now() + make_interval(secs => $3))
	             ON CONFLICT (name) DO UPDATE
	               SET holder = EXCLUDED.holder, acquired_at = now(), expires_at = EXCLUDED.expires_at
	               WHERE leader_leases.expires_at < now() OR leader_leases.holder = EXCLUDED.holder`
	tag, err := s.pool.Exec(ctx, sql, name, holder, ttl.Seconds())
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (s *pgStore) renew(ctx context.Context, name, holder string, ttl time.Duration) (bool, error) {
	const sql = `UPDATE leader_leases SET expires_at = now() + make_interval(secs => $3)
	             WHERE name = $1 AND holder = $2 AND expires_at > now()`
	tag, err := s.pool.Exec(ctx, sql, name, holder, ttl.Seconds())
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (s *pgStore) release(ctx context.Context, name, holder string) error {
	const sql = `DELETE FROM leader_leases WHERE name = $1 AND holder = $2`
	_, err := s.pool.Exec(ctx, sql, name, holder)
	return err
}
