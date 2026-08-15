package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// ErrInstanceNotFound is returned when an instance does not exist.
var ErrInstanceNotFound = errors.New("inventory: instance not found")

// ListFilters narrows instance queries for the console.
type ListFilters struct {
	ClusterID string
	ItemID    string
	Health    string
	OwnerTeam string
}

// Store is the PostgreSQL projection of resource instances (plan §5.9).
type Store struct{}

func NewStore() *Store { return &Store{} }

const instanceCols = `id, org_id, cluster_id, catalog_item_id, version, owner_team, spec, resource_ref,
                      health, sync_state, status_message, state, management_mode, commit_sha, pr_url,
                      generation, created_at, updated_at`

func scanInstance(row pgx.Row) (*types.ResourceInstance, error) {
	var it types.ResourceInstance
	var ref json.RawMessage
	err := row.Scan(&it.ID, &it.OrgID, &it.ClusterID, &it.CatalogItemID, &it.Version, &it.OwnerTeam,
		&it.Spec, &ref, &it.Health, &it.SyncState, &it.StatusMessage, &it.State, &it.ManagementMode,
		&it.CommitSHA, &it.PRURL, &it.Generation, &it.CreatedAt, &it.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if len(ref) > 0 {
		_ = json.Unmarshal(ref, &it.ResourceRef)
	}
	return &it, nil
}

func (s *Store) Create(ctx context.Context, q db.Querier, it *types.ResourceInstance) error {
	ref, err := json.Marshal(it.ResourceRef)
	if err != nil {
		return err
	}
	const sql = `INSERT INTO resource_instances
	               (id, org_id, cluster_id, catalog_item_id, version, owner_team, spec, resource_ref,
	                health, sync_state, status_message, state, management_mode, commit_sha, pr_url, generation)
	             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`
	_, err = q.Exec(ctx, sql, it.ID, it.OrgID, it.ClusterID, it.CatalogItemID, it.Version, it.OwnerTeam,
		it.Spec, ref, it.Health, it.SyncState, it.StatusMessage, it.State, it.ManagementMode,
		it.CommitSHA, it.PRURL, it.Generation)
	return err
}

func (s *Store) Get(ctx context.Context, q db.Querier, id string) (*types.ResourceInstance, error) {
	it, err := scanInstance(q.QueryRow(ctx, `SELECT `+instanceCols+` FROM resource_instances WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInstanceNotFound
	}
	return it, err
}

func (s *Store) List(ctx context.Context, q db.Querier, orgID string, f ListFilters) ([]types.ResourceInstance, error) {
	sql := `SELECT ` + instanceCols + ` FROM resource_instances WHERE org_id = $1`
	args := []any{orgID}
	addEq := func(field, v string) {
		if v != "" {
			args = append(args, v)
			sql += fmt.Sprintf(" AND %s = $%d", field, len(args))
		}
	}
	addEq("cluster_id", f.ClusterID)
	addEq("catalog_item_id", f.ItemID)
	addEq("health", f.Health)
	addEq("owner_team", f.OwnerTeam)
	sql += ` ORDER BY created_at DESC`
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.ResourceInstance
	for rows.Next() {
		it, err := scanInstance(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *it)
	}
	return out, rows.Err()
}

// ApplyStatus updates health/sync/message/state from an agent status-update.
// Returns the updated instance and whether it matched an existing row.
func (s *Store) ApplyStatus(ctx context.Context, q db.Querier, clusterID string, ref types.ResourceRef,
	health, syncState, message string, state types.InstanceState) (*types.ResourceInstance, bool, error) {
	const sql = `UPDATE resource_instances
	             SET health = $3, sync_state = $4, status_message = $5, state = $6, updated_at = now()
	             WHERE cluster_id = $1
	               AND resource_ref->>'kind' = $2
	               AND resource_ref->>'name' = $7
	               AND COALESCE(resource_ref->>'namespace','') = $8
	             RETURNING ` + instanceCols
	it, err := scanInstance(q.QueryRow(ctx, sql, clusterID, ref.Kind, health, syncState, message, state, ref.Name, ref.Namespace))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return it, true, nil
}

// MarkDeployed records the git outcome of a deploy/upgrade.
func (s *Store) MarkDeployed(ctx context.Context, q db.Querier, id, version, commitSHA, prURL string, state types.InstanceState, bumpGeneration bool) error {
	sql := `UPDATE resource_instances
	        SET version = $2, commit_sha = $3, pr_url = $4, state = $5, updated_at = now()`
	if bumpGeneration {
		sql += `, generation = generation + 1`
	}
	sql += ` WHERE id = $1`
	tag, err := q.Exec(ctx, sql, id, version, commitSHA, prURL, state)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrInstanceNotFound
	}
	return nil
}

// GitConfig reads the tenant's git target.
func (s *Store) GitConfig(ctx context.Context, q db.Querier, orgID string) (*types.TenantGitConfig, error) {
	var c types.TenantGitConfig
	err := q.QueryRow(ctx, `SELECT org_id, repo, commit_policy, base_branch FROM tenant_git_configs WHERE org_id = $1`, orgID).
		Scan(&c.OrgID, &c.Repo, &c.CommitPolicy, &c.BaseBranch)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &c, err
}

// UpsertGitConfig sets the tenant's git target + commit policy.
func (s *Store) UpsertGitConfig(ctx context.Context, q db.Querier, c *types.TenantGitConfig) error {
	const sql = `INSERT INTO tenant_git_configs (org_id, repo, commit_policy, base_branch) VALUES ($1,$2,$3,$4)
	             ON CONFLICT (org_id) DO UPDATE SET repo = EXCLUDED.repo, commit_policy = EXCLUDED.commit_policy,
	               base_branch = EXCLUDED.base_branch`
	_, err := q.Exec(ctx, sql, c.OrgID, c.Repo, c.CommitPolicy, c.BaseBranch)
	return err
}
