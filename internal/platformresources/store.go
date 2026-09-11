package platformresources

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// ErrResourceNotFound is returned when a platform resource does not exist.
var ErrResourceNotFound = errors.New("platformresources: resource not found")

// Store is the PostgreSQL projection of tenant platform resources (M7).
type Store struct{}

func NewStore() *Store { return &Store{} }

const resourceCols = `id, org_id, kind, name, desired, status, detail, reported_at, created_at, updated_at`

func scanResource(row pgx.Row) (*types.PlatformResource, error) {
	var r types.PlatformResource
	err := row.Scan(&r.ID, &r.OrgID, &r.Kind, &r.Name, &r.Desired, &r.Status, &r.Detail,
		&r.ReportedAt, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) Get(ctx context.Context, q db.Querier, id string) (*types.PlatformResource, error) {
	r, err := scanResource(q.QueryRow(ctx, `SELECT `+resourceCols+` FROM platform_resources WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrResourceNotFound
	}
	return r, err
}

func (s *Store) List(ctx context.Context, q db.Querier, orgID string) ([]types.PlatformResource, error) {
	rows, err := q.Query(ctx, `SELECT `+resourceCols+` FROM platform_resources WHERE org_id = $1 ORDER BY kind, name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []types.PlatformResource{}
	for rows.Next() {
		r, err := scanResource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// UpsertDesired inserts the desired state for (org_id, kind, name) or updates
// it when changed. The bool reports whether the row was inserted or its
// desired state actually changed (event-level idempotency).
func (s *Store) UpsertDesired(ctx context.Context, q db.Querier, r *types.PlatformResource) (*types.PlatformResource, bool, error) {
	const upsert = `INSERT INTO platform_resources (id, org_id, kind, name, desired)
	             VALUES ($1, $2, $3, $4, $5)
	             ON CONFLICT (org_id, kind, name) DO UPDATE
	               SET desired = EXCLUDED.desired, updated_at = now()
	               WHERE platform_resources.desired IS DISTINCT FROM EXCLUDED.desired
	             RETURNING ` + resourceCols
	got, err := scanResource(q.QueryRow(ctx, upsert, r.ID, r.OrgID, r.Kind, r.Name, r.Desired))
	if err == nil {
		return got, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, err
	}
	// No change: fetch the current row.
	got, err = scanResource(q.QueryRow(ctx,
		`SELECT `+resourceCols+` FROM platform_resources WHERE org_id = $1 AND kind = $2 AND name = $3`,
		r.OrgID, r.Kind, r.Name))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, ErrResourceNotFound
	}
	if err != nil {
		return nil, false, err
	}
	return got, false, nil
}

// ApplyStatus records the agent-reported status for the (kind, name) row.
// Returns the updated resource and whether it matched an existing row.
func (s *Store) ApplyStatus(ctx context.Context, q db.Querier, kind types.PlatformResourceKind, name string,
	status types.PlatformResourceStatus, detail string, reportedAt *time.Time) (*types.PlatformResource, bool, error) {
	const sql = `UPDATE platform_resources
	             SET status = $3, detail = $4, reported_at = COALESCE($5, now()), updated_at = now()
	             WHERE kind = $1 AND name = $2
	             RETURNING ` + resourceCols
	r, err := scanResource(q.QueryRow(ctx, sql, kind, name, status, detail, reportedAt))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return r, true, nil
}
