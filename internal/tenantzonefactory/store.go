// PostgreSQL projection of tenant zone state (plan §5.12): zone records
// plus their resumable step sub-resources.
package tenantzonefactory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// ErrZoneNotFound is returned for unknown zones.
var ErrZoneNotFound = errors.New("tzf: zone not found")

// ErrSlugTaken is returned when the zone slug is already in use.
var ErrSlugTaken = errors.New("tzf: zone slug already in use")

// Store persists tenant zones and their steps.
type Store struct{}

// NewStore returns the zone store.
func NewStore() *Store { return &Store{} }

const zoneCols = `id, slug, display_name, owner_org_id, org_id, ou_id, region, tier, state,
	management_account_id, aws_account_id, cluster_id, cloud_account_id, keycloak_org_id,
	git_repo, tags, error, created_by, created_at, updated_at`

func scanZone(row interface{ Scan(...any) error }) (*types.TenantZone, error) {
	var z types.TenantZone
	var tags []byte
	err := row.Scan(&z.ID, &z.Slug, &z.DisplayName, &z.OwnerOrgID, &z.OrgID, &z.OUID, &z.Region,
		&z.Tier, &z.State, &z.ManagementAccountID, &z.AWSAccountID, &z.ClusterID, &z.CloudAccountID,
		&z.KeycloakOrgID, &z.GitRepo, &tags, &z.Error, &z.CreatedBy, &z.CreatedAt, &z.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if len(tags) > 0 {
		if err := json.Unmarshal(tags, &z.Tags); err != nil {
			return nil, fmt.Errorf("tzf: zone tags: %w", err)
		}
	}
	return &z, nil
}

// CreateZone inserts a new zone in the requested state.
func (s *Store) CreateZone(ctx context.Context, q db.Querier, z *types.TenantZone) error {
	tags, err := json.Marshal(z.Tags)
	if err != nil {
		return err
	}
	const sql = `INSERT INTO tenant_zones (id, slug, display_name, owner_org_id, ou_id, region, tier,
	             state, management_account_id, tags, created_by)
	             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING ` + zoneCols
	out, err := scanZone(q.QueryRow(ctx, sql, z.ID, z.Slug, z.DisplayName, z.OwnerOrgID, z.OUID,
		z.Region, z.Tier, z.State, z.ManagementAccountID, tags, z.CreatedBy))
	if isSlugUniqueViolation(err) {
		return ErrSlugTaken
	}
	if err != nil {
		return err
	}
	*z = *out
	return nil
}

// GetZone loads one zone by ID.
func (s *Store) GetZone(ctx context.Context, q db.Querier, id string) (*types.TenantZone, error) {
	const sql = `SELECT ` + zoneCols + ` FROM tenant_zones WHERE id = $1`
	z, err := scanZone(q.QueryRow(ctx, sql, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrZoneNotFound
	}
	return z, err
}

// ListZones returns the zones owned by an org (via its management account).
func (s *Store) ListZones(ctx context.Context, q db.Querier, ownerOrgID string) ([]types.TenantZone, error) {
	const sql = `SELECT ` + zoneCols + ` FROM tenant_zones WHERE owner_org_id = $1 ORDER BY created_at`
	rows, err := q.Query(ctx, sql, ownerOrgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.TenantZone
	for rows.Next() {
		z, err := scanZone(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *z)
	}
	return out, rows.Err()
}

// ListResumable returns zones in a state the reconcile loop drives.
func (s *Store) ListResumable(ctx context.Context, q db.Querier) ([]types.TenantZone, error) {
	const sql = `SELECT ` + zoneCols + ` FROM tenant_zones
	             WHERE state IN ('provisioning','wiring','cordoning','draining','decommissioning')
	             ORDER BY updated_at`
	rows, err := q.Query(ctx, sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.TenantZone
	for rows.Next() {
		z, err := scanZone(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *z)
	}
	return out, rows.Err()
}

// UpdateZone persists mutable zone fields after step transitions.
func (s *Store) UpdateZone(ctx context.Context, q db.Querier, z *types.TenantZone) error {
	const sql = `UPDATE tenant_zones SET org_id=$2, state=$3, aws_account_id=$4, cluster_id=$5,
	             cloud_account_id=$6, keycloak_org_id=$7, git_repo=$8, error=$9, updated_at=now()
	             WHERE id=$1`
	tag, err := q.Exec(ctx, sql, z.ID, z.OrgID, z.State, z.AWSAccountID, z.ClusterID,
		z.CloudAccountID, z.KeycloakOrgID, z.GitRepo, z.Error)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrZoneNotFound
	}
	return nil
}

// UpsertStep persists one step transition (idempotent by zone+step).
func (s *Store) UpsertStep(ctx context.Context, q db.Querier, st *types.TenantZoneStep) error {
	detail := st.Detail
	if len(detail) == 0 {
		detail = json.RawMessage(`{}`)
	}
	const sql = `INSERT INTO tenant_zone_steps (zone_id, step, status, external_ref, detail, attempts, updated_at)
	             VALUES ($1,$2,$3,$4,$5,$6,now())
	             ON CONFLICT (zone_id, step) DO UPDATE SET
	               status = EXCLUDED.status, external_ref = EXCLUDED.external_ref,
	               detail = EXCLUDED.detail, attempts = EXCLUDED.attempts, updated_at = now()`
	_, err := q.Exec(ctx, sql, st.ZoneID, st.Step, st.Status, st.ExternalRef, detail, st.Attempts)
	return err
}

// ListSteps returns all steps of a zone keyed by step name.
func (s *Store) ListSteps(ctx context.Context, q db.Querier, zoneID string) (map[string]*types.TenantZoneStep, error) {
	const sql = `SELECT zone_id, step, status, external_ref, detail, attempts, updated_at
	             FROM tenant_zone_steps WHERE zone_id = $1`
	rows, err := q.Query(ctx, sql, zoneID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*types.TenantZoneStep{}
	for rows.Next() {
		var st types.TenantZoneStep
		if err := rows.Scan(&st.ZoneID, &st.Step, &st.Status, &st.ExternalRef, &st.Detail, &st.Attempts, &st.UpdatedAt); err != nil {
			return nil, err
		}
		out[st.Step] = &st
	}
	return out, rows.Err()
}

// isSlugUniqueViolation reports whether err is the tenant_zones slug
// unique-constraint violation specifically — a PK collision on id must
// surface as-is, not be misreported as ErrSlugTaken.
func isSlugUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "tenant_zones_slug_key"
}
