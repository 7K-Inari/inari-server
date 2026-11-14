package resourcetargets

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/oklog/ulid/v2"

	"github.com/7K-Inari/inari-server/internal/db"
)

type Store struct{}

func NewStore() *Store { return &Store{} }

const targetColumns = `id, org_id, name, resource_kind, resource_id, capability, config,
	enabled, is_default, revision, created_by, created_at, updated_at`

func scanTarget(row pgx.Row) (*Target, error) {
	var t Target
	var ref TargetResourceRef
	var capability string
	if err := row.Scan(&t.ID, &t.OrgID, &t.Name, &ref.Kind, &ref.ID, &capability, &t.Config,
		&t.Enabled, &t.IsDefault, &t.Revision, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, err
	}
	t.ResourceRef = ref
	t.Capabilities = []string{capability}
	return &t, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func (s *Store) Create(ctx context.Context, q db.Querier, target *Target) error {
	if target.ID == "" {
		target.ID = ulid.Make().String()
	}
	if len(target.Config) == 0 {
		target.Config = []byte(`{}`)
	}
	if target.Revision == 0 {
		target.Revision = 1
	}
	const sql = `INSERT INTO resource_targets
		(id, org_id, name, resource_kind, resource_id, capability, config, enabled, is_default, revision, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING created_at, updated_at`
	err := q.QueryRow(ctx, sql, target.ID, target.OrgID, target.Name, target.ResourceRef.Kind, target.ResourceRef.ID,
		target.Capability(), target.Config, target.Enabled, target.IsDefault, target.Revision, target.CreatedBy).
		Scan(&target.CreatedAt, &target.UpdatedAt)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

func (s *Store) Get(ctx context.Context, q db.Querier, orgID, id string) (*Target, error) {
	t, err := scanTarget(q.QueryRow(ctx, `SELECT `+targetColumns+` FROM resource_targets WHERE org_id=$1 AND id=$2`, orgID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTargetNotFound
	}
	return t, err
}

func (s *Store) GetByResource(ctx context.Context, q db.Querier, orgID, capability string, ref TargetResourceRef) (*Target, error) {
	t, err := scanTarget(q.QueryRow(ctx, `SELECT `+targetColumns+` FROM resource_targets
		WHERE org_id=$1 AND capability=$2 AND resource_kind=$3 AND resource_id=$4`, orgID, capability, ref.Kind, ref.ID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTargetNotFound
	}
	return t, err
}

func (s *Store) List(ctx context.Context, q db.Querier, orgID, capability string) ([]*Target, error) {
	sql := `SELECT ` + targetColumns + ` FROM resource_targets WHERE org_id=$1`
	args := []any{orgID}
	if capability != "" {
		args = append(args, capability)
		sql += ` AND capability=$2`
	}
	sql += ` ORDER BY name, id`
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Target
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ListAll feeds authorization convergence. Deleting organizations are skipped
// so this reconciler cannot resurrect tuples retracted by tenant teardown.
func (s *Store) ListAll(ctx context.Context, q db.Querier) ([]*Target, error) {
	rows, err := q.Query(ctx, `SELECT `+targetColumns+` FROM resource_targets rt
		JOIN organizations o ON o.id=rt.org_id AND o.status='active' ORDER BY rt.org_id, rt.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Target
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) Update(ctx context.Context, q db.Querier, target *Target, expectedRevision int64) error {
	const sql = `UPDATE resource_targets SET name=$3, config=$4, enabled=$5, is_default=$6,
		revision=revision+1, updated_at=now()
		WHERE org_id=$1 AND id=$2 AND revision=$7 RETURNING revision, updated_at`
	err := q.QueryRow(ctx, sql, target.OrgID, target.ID, target.Name, target.Config, target.Enabled,
		target.IsDefault, expectedRevision).Scan(&target.Revision, &target.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrStaleRevision
	}
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

func (s *Store) Delete(ctx context.Context, q db.Querier, orgID, id string) error {
	tag, err := q.Exec(ctx, `DELETE FROM resource_targets WHERE org_id=$1 AND id=$2`, orgID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrTargetNotFound
	}
	return nil
}

func (s *Store) ClearDefault(ctx context.Context, q db.Querier, orgID, capability, exceptID string) error {
	_, err := q.Exec(ctx, `UPDATE resource_targets SET is_default=false, revision=revision+1, updated_at=now()
		WHERE org_id=$1 AND capability=$2 AND is_default AND id<>$3`, orgID, capability, exceptID)
	return err
}

func (s *Store) SetGrant(ctx context.Context, q db.Querier, grant *Grant) error {
	const sql = `INSERT INTO resource_target_grants (target_id, team_id, relation, created_by)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (target_id, team_id) DO UPDATE SET relation=EXCLUDED.relation, updated_at=now()
		RETURNING created_at, updated_at`
	return q.QueryRow(ctx, sql, grant.TargetID, grant.TeamID, grant.Relation, grant.CreatedBy).
		Scan(&grant.CreatedAt, &grant.UpdatedAt)
}

func (s *Store) GetGrant(ctx context.Context, q db.Querier, orgID, targetID, teamID string) (*Grant, error) {
	var g Grant
	err := q.QueryRow(ctx, `SELECT g.target_id, g.team_id, g.relation, g.created_by, g.created_at, g.updated_at
		FROM resource_target_grants g JOIN resource_targets rt ON rt.id=g.target_id
		WHERE rt.org_id=$1 AND g.target_id=$2 AND g.team_id=$3`, orgID, targetID, teamID).
		Scan(&g.TargetID, &g.TeamID, &g.Relation, &g.CreatedBy, &g.CreatedAt, &g.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTargetNotFound
	}
	return &g, err
}

func (s *Store) DeleteGrant(ctx context.Context, q db.Querier, orgID, targetID, teamID string) error {
	tag, err := q.Exec(ctx, `DELETE FROM resource_target_grants g USING resource_targets rt
		WHERE rt.id=g.target_id AND rt.org_id=$1 AND g.target_id=$2 AND g.team_id=$3`, orgID, targetID, teamID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrTargetNotFound
	}
	return nil
}

func (s *Store) ListGrants(ctx context.Context, q db.Querier, orgID, targetID string) ([]Grant, error) {
	rows, err := q.Query(ctx, `SELECT g.target_id, g.team_id, g.relation, g.created_by, g.created_at, g.updated_at
		FROM resource_target_grants g JOIN resource_targets rt ON rt.id=g.target_id
		WHERE rt.org_id=$1 AND g.target_id=$2 ORDER BY g.team_id`, orgID, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		var g Grant
		if err := rows.Scan(&g.TargetID, &g.TeamID, &g.Relation, &g.CreatedBy, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// ListGrantsForOrg batches manager descriptor grants by target ID.
func (s *Store) ListGrantsForOrg(ctx context.Context, q db.Querier, orgID string) (map[string][]Grant, error) {
	rows, err := q.Query(ctx, `SELECT g.target_id, g.team_id, g.relation, g.created_by, g.created_at, g.updated_at
		FROM resource_target_grants g JOIN resource_targets rt ON rt.id=g.target_id
		WHERE rt.org_id=$1 ORDER BY g.target_id, g.team_id`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]Grant{}
	for rows.Next() {
		var g Grant
		if err := rows.Scan(&g.TargetID, &g.TeamID, &g.Relation, &g.CreatedBy, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		out[g.TargetID] = append(out[g.TargetID], g)
	}
	return out, rows.Err()
}

// GrantAllows is a narrowing revocation fence, not a replacement for OpenFGA.
// It joins the current membership/grant projections so deleted or downgraded
// grants deny immediately even while an older cached FGA allow still exists.
func (s *Store) GrantAllows(ctx context.Context, q db.Querier, orgID, subject string, targetIDs []string, action Action) (map[string]bool, error) {
	out := map[string]bool{}
	if len(targetIDs) == 0 {
		return out, nil
	}
	subject = strings.TrimPrefix(subject, "user:")
	const sql = `SELECT DISTINCT g.target_id FROM resource_target_grants g
		JOIN resource_targets rt ON rt.id=g.target_id AND rt.org_id=$1
		JOIN memberships m ON m.team_id=g.team_id AND m.org_id=rt.org_id AND m.user_id=$2
		WHERE g.target_id=ANY($3) AND (
			($4='view' AND g.relation IN ('view','use','provision')) OR
			($4='use' AND g.relation='use') OR
			($4='provision' AND g.relation='provision'))`
	rows, err := q.Query(ctx, sql, orgID, subject, targetIDs, string(action))
	if err != nil {
		return nil, fmt.Errorf("resourcetargets: grant fence: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}
