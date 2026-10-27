package inventory

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/oklog/ulid/v2"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// ErrInstanceNotFound is returned when an instance does not exist.
var ErrInstanceNotFound = errors.New("inventory: instance not found")

// ErrRepoNotFound is returned when a git repo row does not exist.
var ErrRepoNotFound = errors.New("inventory: git repo not found")

// ErrAddonNotFound is returned when a cluster addon row does not exist.
var ErrAddonNotFound = errors.New("inventory: cluster addon not found")

// ErrRepoInUse is returned when a repo cannot be deleted (e.g. it is the
// org default).
var ErrRepoInUse = errors.New("inventory: git repo in use")

// ErrTeamNotInOrg is returned when a repo write references a team owned by
// a different org (cross-org team references are an authorization leak:
// the team filter in ListGitRepos would show the repo to the foreign team).
var ErrTeamNotInOrg = errors.New("inventory: team does not belong to org")

// newULID returns a new ULID string for registry rows.
func newULID() string {
	return ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()
}

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
                      repo_id, generation, created_at, updated_at`

func scanInstance(row pgx.Row) (*types.ResourceInstance, error) {
	var it types.ResourceInstance
	var ref json.RawMessage
	var repoID *string
	err := row.Scan(&it.ID, &it.OrgID, &it.ClusterID, &it.CatalogItemID, &it.Version, &it.OwnerTeam,
		&it.Spec, &ref, &it.Health, &it.SyncState, &it.StatusMessage, &it.State, &it.ManagementMode,
		&it.CommitSHA, &it.PRURL, &repoID, &it.Generation, &it.CreatedAt, &it.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if len(ref) > 0 {
		_ = json.Unmarshal(ref, &it.ResourceRef)
	}
	if repoID != nil {
		it.RepoID = *repoID
	}
	return &it, nil
}

func (s *Store) Create(ctx context.Context, q db.Querier, it *types.ResourceInstance) error {
	ref, err := json.Marshal(it.ResourceRef)
	if err != nil {
		return err
	}
	var repoID *string
	if it.RepoID != "" {
		repoID = &it.RepoID
	}
	const sql = `INSERT INTO resource_instances
	               (id, org_id, cluster_id, catalog_item_id, version, owner_team, spec, resource_ref,
	                health, sync_state, status_message, state, management_mode, commit_sha, pr_url, repo_id, generation)
	             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`
	_, err = q.Exec(ctx, sql, it.ID, it.OrgID, it.ClusterID, it.CatalogItemID, it.Version, it.OwnerTeam,
		it.Spec, ref, it.Health, it.SyncState, it.StatusMessage, it.State, it.ManagementMode,
		it.CommitSHA, it.PRURL, repoID, it.Generation)
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

// Delete removes an instance row (undeploy).
func (s *Store) Delete(ctx context.Context, q db.Querier, id string) error {
	tag, err := q.Exec(ctx, `DELETE FROM resource_instances WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrInstanceNotFound
	}
	return nil
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

// MarkDeployed records the git outcome of a deploy/upgrade. repoID
// backfills the instance's repo attribution (Feature A): a legacy NULL row
// self-heals to the repo the mutation just wrote; an already-attributed row
// is never moved (repo immutability).
func (s *Store) MarkDeployed(ctx context.Context, q db.Querier, id, version, commitSHA, prURL, repoID string, state types.InstanceState, bumpGeneration bool) error {
	sql := `UPDATE resource_instances
        SET version = $2, commit_sha = $3, pr_url = $4, state = $5, updated_at = now(),
            repo_id = COALESCE(repo_id, NULLIF($6, ''))`
	if bumpGeneration {
		sql += `, generation = generation + 1`
	}
	sql += ` WHERE id = $1`
	tag, err := q.Exec(ctx, sql, id, version, commitSHA, prURL, state, repoID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrInstanceNotFound
	}
	return nil
}

// MarkSpecUpdated records a spec-only update (same version): stores the new
// spec plus the git outcome and bumps the generation. repoID backfills the
// repo attribution the same way MarkDeployed does.
func (s *Store) MarkSpecUpdated(ctx context.Context, q db.Querier, id string, spec json.RawMessage, commitSHA, prURL, repoID string, state types.InstanceState) error {
	const sql = `UPDATE resource_instances
             SET spec = $2, commit_sha = $3, pr_url = $4, state = $5,
                 generation = generation + 1, updated_at = now(),
                 repo_id = COALESCE(repo_id, NULLIF($6, ''))
             WHERE id = $1`
	tag, err := q.Exec(ctx, sql, id, spec, commitSHA, prURL, state, repoID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrInstanceNotFound
	}
	return nil
}

// ApplyAppStatus updates an instance from its backing ArgoCD Application
// (matched by ID). The app is the source of truth for app-backed instances,
// so state always follows it (a bogus healthy can be corrected on the next
// update); the message always updates so sync/render errors reach the
// console.
func (s *Store) ApplyAppStatus(ctx context.Context, q db.Querier, id, health, syncState, message string, state types.InstanceState) error {
	const sql = `UPDATE resource_instances
	             SET health = $2, sync_state = $3, status_message = $4, state = $5, updated_at = now()
	             WHERE id = $1`
	_, err := q.Exec(ctx, sql, id, health, syncState, message, state)
	return err
}

// MarkFailed moves an instance out of deploying/upgrading into failed with
// the given message (e.g. the agent NACKed the app registration). It never
// clobbers running/degraded instances whose status came from live reports.
func (s *Store) MarkFailed(ctx context.Context, q db.Querier, id, message string) error {
	const sql = `UPDATE resource_instances
	             SET state = 'failed', status_message = $2, updated_at = now()
	             WHERE id = $1 AND state IN ('deploying', 'upgrading', 'pending')`
	tag, err := q.Exec(ctx, sql, id, message)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrInstanceNotFound
	}
	return nil
}

// GitConfig reads the tenant's git target. Repo/CommitPolicy/BaseBranch are
// a back-compat proxy: when the org has a default row in tenant_git_repos,
// that row's values win; otherwise the legacy tenant_git_configs columns are
// returned.
func (s *Store) GitConfig(ctx context.Context, q db.Querier, orgID string) (*types.TenantGitConfig, error) {
	var c types.TenantGitConfig
	var scaffoldOrg, keySecret, keyKey, apiBase, userFallback *string
	var appID, installationID *int64
	err := q.QueryRow(ctx, `SELECT org_id, repo, commit_policy, base_branch, scaffold_git_org,
		github_app_id, github_app_installation_id, github_app_key_secret, github_app_key_key, github_app_api_base,
		user_template_fallback
		FROM tenant_git_configs WHERE org_id = $1`, orgID).
		Scan(&c.OrgID, &c.Repo, &c.CommitPolicy, &c.BaseBranch, &scaffoldOrg,
			&appID, &installationID, &keySecret, &keyKey, &apiBase, &userFallback)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// Back-compat proxy: the registry's default repo is authoritative for
	// repo/policy/branch (a PATCH on the git-repos API must not leave this
	// legacy view stale).
	var defaultRepo, defaultPolicy, defaultBranch *string
	if err := q.QueryRow(ctx, `SELECT repo, commit_policy, base_branch FROM tenant_git_repos WHERE org_id = $1 AND is_default`, orgID).
		Scan(&defaultRepo, &defaultPolicy, &defaultBranch); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if defaultRepo != nil {
		c.Repo = *defaultRepo
	}
	if defaultPolicy != nil {
		c.CommitPolicy = types.CommitPolicy(*defaultPolicy)
	}
	if defaultBranch != nil {
		c.BaseBranch = *defaultBranch
	}
	if scaffoldOrg != nil {
		c.ScaffoldGitOrg = *scaffoldOrg
	}
	if userFallback != nil {
		c.UserTemplateFallback = *userFallback
	}
	if appID != nil {
		c.GitHubApp = gitAppFromColumns(*appID, installationID, keySecret, keyKey, apiBase)
	}
	return &c, nil
}

// packGitHubAppColumns flattens a BYO app reference into its storage
// columns. A nil KeyRef is rejected here: persisting it would violate the
// all-or-nothing CHECK constraint (app id set, key ref NULL) and a nil
// dereference must never escape the store.
func packGitHubAppColumns(app *types.GitHubAppConfig) (appID, installationID *int64, keySecret, keyKey, apiBase *string, err error) {
	if app == nil {
		return nil, nil, nil, nil, nil, nil
	}
	if app.KeyRef == nil {
		return nil, nil, nil, nil, nil, errors.New("inventory: github app keyRef is required")
	}
	appID = &app.AppID
	installationID = &app.InstallationID
	packed := app.KeyRef.Namespace + "/" + app.KeyRef.SecretName
	keySecret = &packed
	keyKey = &app.KeyRef.Key
	if app.APIBase != "" {
		apiBase = &app.APIBase
	}
	return appID, installationID, keySecret, keyKey, apiBase, nil
}

// gitAppFromColumns rebuilds the BYO app reference from storage. The
// namespace/name pair is packed in one column (validated at write time).
func gitAppFromColumns(appID int64, installationID *int64, keySecret, keyKey, apiBase *string) *types.GitHubAppConfig {
	app := &types.GitHubAppConfig{AppID: appID, KeyRef: &types.GitHubAppSecretRef{}}
	if installationID != nil {
		app.InstallationID = *installationID
	}
	if keySecret != nil {
		if i := strings.Index(*keySecret, "/"); i > 0 {
			app.KeyRef.Namespace = (*keySecret)[:i]
			app.KeyRef.SecretName = (*keySecret)[i+1:]
		} else {
			app.KeyRef.SecretName = *keySecret
		}
	}
	if keyKey != nil {
		app.KeyRef.Key = *keyKey
	}
	if apiBase != nil {
		app.APIBase = *apiBase
	}
	return app
}

// UpsertGitConfig sets the tenant's git target + commit policy.
func (s *Store) UpsertGitConfig(ctx context.Context, q db.Querier, c *types.TenantGitConfig) error {
	var scaffoldOrg *string
	if c.ScaffoldGitOrg != "" {
		scaffoldOrg = &c.ScaffoldGitOrg
	}
	var userFallback *string
	if c.UserTemplateFallback != "" {
		userFallback = &c.UserTemplateFallback
	}
	var appID, installationID *int64
	var keySecret, keyKey, apiBase *string
	if c.GitHubApp != nil {
		var err error
		appID, installationID, keySecret, keyKey, apiBase, err = packGitHubAppColumns(c.GitHubApp)
		if err != nil {
			return err
		}
	}
	// An omitted githubApp must not wipe the stored reference (a writer
	// like the tenant zone factory doesn't know about it); an explicit
	// ClearGitHubApp NULLs the BYO columns, reverting the tenant to model A.
	byoClause := `github_app_id = COALESCE(EXCLUDED.github_app_id, tenant_git_configs.github_app_id),
		  github_app_installation_id = COALESCE(EXCLUDED.github_app_installation_id, tenant_git_configs.github_app_installation_id),
		  github_app_key_secret = COALESCE(EXCLUDED.github_app_key_secret, tenant_git_configs.github_app_key_secret),
		  github_app_key_key = COALESCE(EXCLUDED.github_app_key_key, tenant_git_configs.github_app_key_key),
		  github_app_api_base = COALESCE(EXCLUDED.github_app_api_base, tenant_git_configs.github_app_api_base)`
	if c.ClearGitHubApp {
		byoClause = `github_app_id = NULL, github_app_installation_id = NULL,
		  github_app_key_secret = NULL, github_app_key_key = NULL, github_app_api_base = NULL`
	}
	const sqlFmt = `INSERT INTO tenant_git_configs
		(org_id, repo, commit_policy, base_branch, scaffold_git_org,
		 github_app_id, github_app_installation_id, github_app_key_secret, github_app_key_key, github_app_api_base,
		 user_template_fallback)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,COALESCE($11,'block'))
		ON CONFLICT (org_id) DO UPDATE SET repo = EXCLUDED.repo, commit_policy = EXCLUDED.commit_policy,
		  base_branch = EXCLUDED.base_branch,
		  -- A writer that doesn't know the override (e.g. the
		  -- tenant zone factory) must not wipe it.
		  scaffold_git_org = COALESCE(EXCLUDED.scaffold_git_org, tenant_git_configs.scaffold_git_org),
		  -- Same preserve-on-omit rule for the user-template fallback
		  -- policy (platform-engineer-only setting): keyed off the raw
		  -- parameter because the INSERT coalesces omit to 'block'.
		  user_template_fallback = CASE WHEN $11 IS NULL THEN tenant_git_configs.user_template_fallback ELSE $11 END,
		  %s`
	_, err := q.Exec(ctx, fmt.Sprintf(sqlFmt, byoClause), c.OrgID, c.Repo, c.CommitPolicy, c.BaseBranch, scaffoldOrg,
		appID, installationID, keySecret, keyKey, apiBase, userFallback)
	if err != nil {
		return err
	}
	// Back-compat proxy: mirror the legacy write onto the org's default
	// tenant_git_repos row, creating it when the org predates the registry
	// (fresh tenants post-migration). This keeps the tenant zone factory and
	// other legacy writers working unchanged.
	return s.syncDefaultRepoFromConfig(ctx, q, c)
}

// syncDefaultRepoFromConfig upserts the org's default platform repo from a
// legacy TenantGitConfig write.
func (s *Store) syncDefaultRepoFromConfig(ctx context.Context, q db.Querier, c *types.TenantGitConfig) error {
	var existing *string
	err := q.QueryRow(ctx, `SELECT id FROM tenant_git_repos WHERE org_id = $1 AND is_default`, c.OrgID).
		Scan(&existing)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if existing == nil {
		repo := &types.TenantGitRepo{
			OrgID:        c.OrgID,
			Name:         "baseline",
			Repo:         c.Repo,
			Provider:     types.GitRepoProviderGitHub,
			Scope:        types.GitRepoScopePlatform,
			CommitPolicy: c.CommitPolicy,
			BaseBranch:   c.BaseBranch,
			IsDefault:    true,
			GitHubApp:    c.GitHubApp,
		}
		return s.UpsertGitRepo(ctx, q, repo)
	}
	// Update the existing default row. BYO columns follow the same
	// preserve-on-omit / ClearGitHubApp semantics as the config write.
	byoSet := `github_app_id = COALESCE($4::bigint, github_app_id),
		github_app_installation_id = COALESCE($5::bigint, github_app_installation_id),
		github_app_key_secret = COALESCE($6::text, github_app_key_secret),
		github_app_key_key = COALESCE($7::text, github_app_key_key),
		github_app_api_base = COALESCE($8::text, github_app_api_base)`
	var appID, installationID *int64
	var keySecret, keyKey, apiBase *string
	if c.GitHubApp != nil {
		var perr error
		appID, installationID, keySecret, keyKey, apiBase, perr = packGitHubAppColumns(c.GitHubApp)
		if perr != nil {
			return perr
		}
	}
	if c.ClearGitHubApp {
		_, err = q.Exec(ctx, `UPDATE tenant_git_repos SET repo = $1, commit_policy = $2, base_branch = $3,
			updated_at = now(), github_app_id = NULL, github_app_installation_id = NULL,
			github_app_key_secret = NULL, github_app_key_key = NULL, github_app_api_base = NULL
			WHERE id = $4`, c.Repo, c.CommitPolicy, c.BaseBranch, *existing)
		return err
	}
	_, err = q.Exec(ctx, fmt.Sprintf(`UPDATE tenant_git_repos SET repo = $1, commit_policy = $2, base_branch = $3,
		updated_at = now(), %s WHERE id = $9`, byoSet),
		c.Repo, c.CommitPolicy, c.BaseBranch, appID, installationID, keySecret, keyKey, apiBase, *existing)
	return err
}

// ---------------------------------------------------------------------------
// Git repo registry (Feature A)

const gitRepoCols = `id, org_id, name, repo, provider, scope, team_id, commit_policy, base_branch,
	is_default, github_app_id, github_app_installation_id, github_app_key_secret,
	github_app_key_key, github_app_api_base, created_at, updated_at`

func scanGitRepo(row pgx.Row) (*types.TenantGitRepo, error) {
	var r types.TenantGitRepo
	var teamID *string
	var appID, installationID *int64
	var keySecret, keyKey, apiBase *string
	err := row.Scan(&r.ID, &r.OrgID, &r.Name, &r.Repo, &r.Provider, &r.Scope, &teamID,
		&r.CommitPolicy, &r.BaseBranch, &r.IsDefault,
		&appID, &installationID, &keySecret, &keyKey, &apiBase, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if teamID != nil {
		r.TeamID = *teamID
	}
	if appID != nil {
		r.GitHubApp = gitAppFromColumns(*appID, installationID, keySecret, keyKey, apiBase)
	}
	return &r, nil
}

// ListGitRepos returns the org's registered repos. An empty teamIDs filter
// returns all repos (platform-team view); a non-empty filter returns
// platform repos plus repos owned by any of the given teams (baseline
// read-all + own teams, plan risk #5 — members may belong to many teams).
func (s *Store) ListGitRepos(ctx context.Context, q db.Querier, orgID string, teamIDs []string) ([]*types.TenantGitRepo, error) {
	sql := `SELECT ` + gitRepoCols + ` FROM tenant_git_repos WHERE org_id = $1`
	args := []any{orgID}
	if len(teamIDs) > 0 {
		args = append(args, teamIDs)
		sql += fmt.Sprintf(` AND (scope = 'platform' OR team_id = ANY($%d::uuid[]))`, len(args))
	}
	sql += ` ORDER BY created_at`
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*types.TenantGitRepo
	for rows.Next() {
		r, err := scanGitRepo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetGitRepo returns one repo by id, scoped to the org.
func (s *Store) GetGitRepo(ctx context.Context, q db.Querier, orgID, id string) (*types.TenantGitRepo, error) {
	r, err := scanGitRepo(q.QueryRow(ctx, `SELECT `+gitRepoCols+` FROM tenant_git_repos WHERE org_id = $1 AND id = $2`, orgID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRepoNotFound
	}
	return r, err
}

// GetDefaultGitRepo returns the org's default repo, or ErrRepoNotFound when
// the org has none.
func (s *Store) GetDefaultGitRepo(ctx context.Context, q db.Querier, orgID string) (*types.TenantGitRepo, error) {
	r, err := scanGitRepo(q.QueryRow(ctx, `SELECT `+gitRepoCols+` FROM tenant_git_repos WHERE org_id = $1 AND is_default`, orgID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRepoNotFound
	}
	return r, err
}

// UpsertGitRepo inserts or updates a repo row (conflict key: org_id+name).
// A new row gets a generated ULID. BYO app columns follow the same
// preserve-on-omit / ClearGitHubApp semantics as UpsertGitConfig.
// is_default is insert-only: promotion/demotion goes exclusively through
// SetDefaultGitRepo, so a re-upsert with the Go zero value cannot strip an
// org's default. A team-scope write referencing another org's team is
// rejected with ErrTeamNotInOrg.
func (s *Store) UpsertGitRepo(ctx context.Context, q db.Querier, r *types.TenantGitRepo) error {
	if r.ID == "" {
		r.ID = newULID()
	}
	if r.Provider == "" {
		r.Provider = types.GitRepoProviderGitHub
	}
	if r.Scope == "" {
		r.Scope = types.GitRepoScopeTeam
	}
	if r.CommitPolicy == "" {
		r.CommitPolicy = types.CommitPolicyDirect
	}
	if r.BaseBranch == "" {
		r.BaseBranch = "main"
	}
	var teamID *string
	if r.TeamID != "" {
		var teamOrg string
		if err := q.QueryRow(ctx, `SELECT org_id FROM teams WHERE id = $1::uuid`, r.TeamID).Scan(&teamOrg); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrTeamNotInOrg
			}
			return err
		}
		if teamOrg != r.OrgID {
			return ErrTeamNotInOrg
		}
		teamID = &r.TeamID
	}
	var appID, installationID *int64
	var keySecret, keyKey, apiBase *string
	if r.GitHubApp != nil {
		var err error
		appID, installationID, keySecret, keyKey, apiBase, err = packGitHubAppColumns(r.GitHubApp)
		if err != nil {
			return err
		}
	}
	byoClause := `github_app_id = COALESCE(EXCLUDED.github_app_id, tenant_git_repos.github_app_id),
		github_app_installation_id = COALESCE(EXCLUDED.github_app_installation_id, tenant_git_repos.github_app_installation_id),
		github_app_key_secret = COALESCE(EXCLUDED.github_app_key_secret, tenant_git_repos.github_app_key_secret),
		github_app_key_key = COALESCE(EXCLUDED.github_app_key_key, tenant_git_repos.github_app_key_key),
		github_app_api_base = COALESCE(EXCLUDED.github_app_api_base, tenant_git_repos.github_app_api_base)`
	if r.ClearGitHubApp {
		byoClause = `github_app_id = NULL, github_app_installation_id = NULL,
			github_app_key_secret = NULL, github_app_key_key = NULL, github_app_api_base = NULL`
	}
	// RETURNING id keeps the caller's row.ID authoritative on the conflict
	// path: ON CONFLICT DO UPDATE keeps the existing row's ID, so without
	// this a retry would hand back the freshly generated, never-stored ULID.
	const sqlFmt = `INSERT INTO tenant_git_repos
		(id, org_id, name, repo, provider, scope, team_id, commit_policy, base_branch, is_default,
		 github_app_id, github_app_installation_id, github_app_key_secret, github_app_key_key, github_app_api_base)
		VALUES ($1,$2,$3,$4,$5,$6,$7::uuid,$8,$9,$10,$11,$12,$13,$14,$15)
		ON CONFLICT (org_id, name) DO UPDATE SET repo = EXCLUDED.repo,
		  provider = EXCLUDED.provider, scope = EXCLUDED.scope, team_id = EXCLUDED.team_id,
		  commit_policy = EXCLUDED.commit_policy, base_branch = EXCLUDED.base_branch,
		  updated_at = now(), %s
		RETURNING id`
	err := q.QueryRow(ctx, fmt.Sprintf(sqlFmt, byoClause),
		r.ID, r.OrgID, r.Name, r.Repo, r.Provider, r.Scope, teamID, r.CommitPolicy, r.BaseBranch, r.IsDefault,
		appID, installationID, keySecret, keyKey, apiBase).Scan(&r.ID)
	return err
}

// DeleteGitRepo unregisters a repo. The org default cannot be deleted
// (promote another repo first); cluster and addon references are nulled by
// ON DELETE SET NULL. Orphan/teardown semantics for live workloads land in
// the handler layer.
func (s *Store) DeleteGitRepo(ctx context.Context, q db.Querier, orgID, id string) error {
	r, err := s.GetGitRepo(ctx, q, orgID, id)
	if err != nil {
		return err
	}
	if r.IsDefault {
		return ErrRepoInUse
	}
	tag, err := q.Exec(ctx, `DELETE FROM tenant_git_repos WHERE org_id = $1 AND id = $2`, orgID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrRepoNotFound
	}
	return nil
}

// SetDefaultGitRepo promotes one repo to the org default, demoting the
// previous one. The flip is a single statement with a forced demote-then-
// promote order (the partial unique index one_default_repo_per_org is
// checked per row, so the old default must clear before the new one sets).
// The demote is gated on the target row existing, so a missing id leaves
// the current default untouched (ErrRepoNotFound) and the org can never
// end up with zero defaults. The default slot is platform-scope only (the
// orchestrator's team-write enforcement skips empty selectors, so a
// team-scope default would be writable by any org member); a team-scope
// target reads as ErrRepoNotFound, leaving the current default untouched.
//
// Concurrency: a per-org pg_advisory_xact_lock serializes flips. Without
// it, two concurrent transactions both pass the demote CTE in their own
// snapshots and the loser's promote collides with the winner's committed
// default on the partial unique index (23505). The lock MUST be its own
// statement: in READ COMMITTED each statement gets a fresh snapshot, so a
// lock taken inside the flip statement would still execute against the
// pre-lock snapshot. Callers must run inside an explicit transaction (the
// gitrepos service's inTx always does); on a bare pool Querier the xact
// lock releases at statement end and the flip degrades to the unsynchronized
// single-statement semantics.
func (s *Store) SetDefaultGitRepo(ctx context.Context, q db.Querier, orgID, id string) error {
	if _, err := q.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtext('tenant_git_repos/default/' || $1))`, orgID); err != nil {
		return err
	}
	const sql = `WITH target AS (
		SELECT id FROM tenant_git_repos WHERE org_id = $1 AND id = $2 AND scope = 'platform'
	), demoted AS (
		UPDATE tenant_git_repos SET is_default = FALSE, updated_at = now()
		WHERE org_id = $1 AND is_default AND EXISTS (SELECT 1 FROM target)
		RETURNING id
	), promoted AS (
		-- The COUNT(*) >= 0 predicate is always true; it exists to force
		-- promoted to run after demoted (data-modifying CTEs otherwise
		-- execute in unspecified order and the unique index would see a
		-- transient double default).
		UPDATE tenant_git_repos SET is_default = TRUE, updated_at = now()
		WHERE id IN (SELECT id FROM target) AND (SELECT COUNT(*) FROM demoted) >= 0
	)
	SELECT COUNT(*) FROM target`
	var n int
	if err := q.QueryRow(ctx, sql, orgID, id).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return ErrRepoNotFound
	}
	return nil
}

// BindClusterBaseline binds a cluster to a platform-scope repo of the same
// org. Returns ErrRepoNotFound when the repo is missing, not platform-scope,
// or belongs to another org.
func (s *Store) BindClusterBaseline(ctx context.Context, q db.Querier, clusterID, repoID string) error {
	tag, err := q.Exec(ctx, `UPDATE clusters c SET baseline_repo_id = r.id
		FROM tenant_git_repos r
		WHERE r.id = $2 AND r.scope = 'platform' AND r.org_id = c.org_id AND c.id = $1`, clusterID, repoID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrRepoNotFound
	}
	return nil
}

// BaselineRepo returns the repo slug ("owner/name") for the cluster's
// bound baseline, or empty when unbound.
func (s *Store) BaselineRepo(ctx context.Context, q db.Querier, clusterID string) (string, error) {
	var repo string
	err := q.QueryRow(ctx, `
		SELECT r.repo FROM clusters c
		JOIN tenant_git_repos r ON r.id = c.baseline_repo_id
		WHERE c.id = $1`, clusterID).Scan(&repo)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return repo, err
}

// BindClusterBaselineToDefault binds a cluster to its org's default
// platform repo. No-op when the org has no default.
func (s *Store) BindClusterBaselineToDefault(ctx context.Context, q db.Querier, clusterID string) error {
	tag, err := q.Exec(ctx, `UPDATE clusters c SET baseline_repo_id = r.id
		FROM tenant_git_repos r
		WHERE r.org_id = c.org_id AND r.is_default AND c.id = $1`, clusterID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrRepoNotFound
	}
	return nil
}

// GitRepoRefCounts counts the live workloads referencing a repo (Feature A
// unregister guard, decision 6): instances recorded against the repo
// (repo_id; pre-0036 rows fall back to their cluster's baseline binding),
// managed addons pointing at the repo, and bound clusters.
// The repo must belong to the org (cross-org reads as zero counts).
func (s *Store) GitRepoRefCounts(ctx context.Context, q db.Querier, orgID, repoID string) (*types.GitRepoRefCounts, error) {
	var c types.GitRepoRefCounts
	err := q.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM resource_instances i
			JOIN clusters c2 ON c2.id = i.cluster_id
			WHERE i.org_id = $1 AND COALESCE(i.repo_id, c2.baseline_repo_id) = $2),
		(SELECT count(*) FROM cluster_addons a
			WHERE a.org_id = $1 AND a.repo_id = $2),
		(SELECT count(*) FROM clusters c3
			WHERE c3.org_id = $1 AND c3.baseline_repo_id = $2)`,
		orgID, repoID).Scan(&c.Instances, &c.Addons, &c.Clusters)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// GitRepoInstanceRef is one instance referencing a repo (its recorded
// repo_id; pre-0036 rows fall back to the cluster's baseline binding), with
// the fields the unregister teardown needs to compute repo paths and
// enqueue ArgoCD app deletions.
type GitRepoInstanceRef struct {
	ID            string
	ClusterID     string
	CatalogItemID string
}

// GitRepoAddonRef is one addon referencing a repo, with the fields the
// unregister teardown needs (repo path + ArgoCD app name + cluster).
type GitRepoAddonRef struct {
	ID         string
	ClusterID  string
	RepoPath   string
	ArgoCDApp  string
	DeployMode string
}

// ListGitRepoInstances returns the instances attributing to the repo (see
// GitRepoRefCounts for the COALESCE fallback rule).
func (s *Store) ListGitRepoInstances(ctx context.Context, q db.Querier, orgID, repoID string) ([]GitRepoInstanceRef, error) {
	rows, err := q.Query(ctx, `SELECT i.id, i.cluster_id, i.catalog_item_id
		FROM resource_instances i JOIN clusters c ON c.id = i.cluster_id
		WHERE i.org_id = $1 AND COALESCE(i.repo_id, c.baseline_repo_id) = $2 ORDER BY i.id`, orgID, repoID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GitRepoInstanceRef
	for rows.Next() {
		var r GitRepoInstanceRef
		if err := rows.Scan(&r.ID, &r.ClusterID, &r.CatalogItemID); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListGitRepoAddons returns the addons referencing the repo directly.
func (s *Store) ListGitRepoAddons(ctx context.Context, q db.Querier, orgID, repoID string) ([]GitRepoAddonRef, error) {
	rows, err := q.Query(ctx, `SELECT id, cluster_id, repo_path, argocd_app, deploy_mode
		FROM cluster_addons WHERE org_id = $1 AND repo_id = $2 ORDER BY id`, orgID, repoID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GitRepoAddonRef
	for rows.Next() {
		var a GitRepoAddonRef
		if err := rows.Scan(&a.ID, &a.ClusterID, &a.RepoPath, &a.ArgoCDApp, &a.DeployMode); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Cluster addons (Feature C schema)

const clusterAddonCols = `id, org_id, cluster_id, catalog_item, state, deploy_mode, repo_id, repo_path,
	source, chart_version, values, argocd_app, health, sync, discovered_meta,
	commit_sha, pr_url, prune_enabled, namespace, cluster_selector, created_at, updated_at`

func scanClusterAddon(row pgx.Row) (*types.ClusterAddon, error) {
	var a types.ClusterAddon
	var repoID *string
	var source, selector []byte
	err := row.Scan(&a.ID, &a.OrgID, &a.ClusterID, &a.CatalogItem, &a.State, &a.DeployMode,
		&repoID, &a.RepoPath, &source, &a.ChartVersion, &a.Values, &a.ArgoCDApp, &a.Health, &a.Sync,
		&a.DiscoveredMeta, &a.CommitSHA, &a.PRURL, &a.PruneEnabled, &a.Namespace, &selector, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if repoID != nil {
		a.RepoID = *repoID
	}
	if err := json.Unmarshal(source, &a.Source); err != nil {
		return nil, fmt.Errorf("inventory: addon %s source: %w", a.ID, err)
	}
	if len(selector) > 0 {
		if err := json.Unmarshal(selector, &a.ClusterSelector); err != nil {
			return nil, fmt.Errorf("inventory: addon %s cluster selector: %w", a.ID, err)
		}
	}
	return &a, nil
}

// ListClusterAddons returns addons for one cluster, or the whole org when
// clusterID is empty.
func (s *Store) ListClusterAddons(ctx context.Context, q db.Querier, orgID, clusterID string) ([]*types.ClusterAddon, error) {
	sql := `SELECT ` + clusterAddonCols + ` FROM cluster_addons WHERE org_id = $1`
	args := []any{orgID}
	if clusterID != "" {
		args = append(args, clusterID)
		sql += fmt.Sprintf(` AND cluster_id = $%d`, len(args))
	}
	sql += ` ORDER BY created_at`
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*types.ClusterAddon
	for rows.Next() {
		a, err := scanClusterAddon(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetClusterAddon returns one addon by (cluster, catalog item).
func (s *Store) GetClusterAddon(ctx context.Context, q db.Querier, orgID, clusterID, catalogItem string) (*types.ClusterAddon, error) {
	a, err := scanClusterAddon(q.QueryRow(ctx, `SELECT `+clusterAddonCols+`
		FROM cluster_addons WHERE org_id = $1 AND cluster_id = $2 AND catalog_item = $3`, orgID, clusterID, catalogItem))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAddonNotFound
	}
	return a, err
}

// UpsertClusterAddon inserts or updates an addon row (conflict key:
// cluster_id+catalog_item). A discovery upsert never downgrades a managed
// row back to discovered (plan §6).
func (s *Store) UpsertClusterAddon(ctx context.Context, q db.Querier, a *types.ClusterAddon) error {
	if a.ID == "" {
		a.ID = newULID()
	}
	if a.State == "" {
		a.State = types.AddonStateDiscovered
	}
	if a.DeployMode == "" {
		a.DeployMode = types.AddonDeployModeApplication
	}
	source, err := json.Marshal(a.Source)
	if err != nil {
		return err
	}
	values := a.Values
	if len(values) == 0 {
		values = json.RawMessage(`{}`)
	}
	var repoID *string
	if a.RepoID != "" {
		repoID = &a.RepoID
	}
	var selector []byte
	if a.ClusterSelector != nil {
		if selector, err = json.Marshal(a.ClusterSelector); err != nil {
			return err
		}
	}
	const sql = `INSERT INTO cluster_addons
		(id, org_id, cluster_id, catalog_item, state, deploy_mode, repo_id, repo_path,
		 source, chart_version, values, argocd_app, health, sync, discovered_meta,
		 commit_sha, pr_url, prune_enabled, namespace, cluster_selector)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
		ON CONFLICT (cluster_id, catalog_item) DO UPDATE SET
		  state = CASE WHEN cluster_addons.state = 'managed' THEN cluster_addons.state ELSE EXCLUDED.state END,
		  deploy_mode = EXCLUDED.deploy_mode,
		  repo_id = COALESCE(EXCLUDED.repo_id, cluster_addons.repo_id),
		  repo_path = CASE WHEN EXCLUDED.repo_path = '' THEN cluster_addons.repo_path ELSE EXCLUDED.repo_path END,
		  source = EXCLUDED.source,
		  chart_version = CASE WHEN EXCLUDED.chart_version = '' THEN cluster_addons.chart_version ELSE EXCLUDED.chart_version END,
		  values = EXCLUDED.values,
		  argocd_app = CASE WHEN EXCLUDED.argocd_app = '' THEN cluster_addons.argocd_app ELSE EXCLUDED.argocd_app END,
		  health = CASE WHEN EXCLUDED.health = '' THEN cluster_addons.health ELSE EXCLUDED.health END,
		  sync = CASE WHEN EXCLUDED.sync = '' THEN cluster_addons.sync ELSE EXCLUDED.sync END,
		  discovered_meta = COALESCE(EXCLUDED.discovered_meta, cluster_addons.discovered_meta),
		  commit_sha = CASE WHEN EXCLUDED.commit_sha = '' THEN cluster_addons.commit_sha ELSE EXCLUDED.commit_sha END,
		  pr_url = CASE WHEN EXCLUDED.pr_url = '' THEN cluster_addons.pr_url ELSE EXCLUDED.pr_url END,
		  prune_enabled = cluster_addons.prune_enabled OR EXCLUDED.prune_enabled,
		  namespace = CASE WHEN EXCLUDED.namespace = '' THEN cluster_addons.namespace ELSE EXCLUDED.namespace END,
		  cluster_selector = COALESCE(EXCLUDED.cluster_selector, cluster_addons.cluster_selector),
		  updated_at = now()`
	_, err = q.Exec(ctx, sql, a.ID, a.OrgID, a.ClusterID, a.CatalogItem, a.State, a.DeployMode,
		repoID, a.RepoPath, source, a.ChartVersion, values, a.ArgoCDApp, a.Health, a.Sync, a.DiscoveredMeta,
		a.CommitSHA, a.PRURL, a.PruneEnabled, a.Namespace, selector)
	return err
}

// GetClusterAddonByID returns one addon by primary key, scoped to the org.
func (s *Store) GetClusterAddonByID(ctx context.Context, q db.Querier, orgID, id string) (*types.ClusterAddon, error) {
	a, err := scanClusterAddon(q.QueryRow(ctx, `SELECT `+clusterAddonCols+`
		FROM cluster_addons WHERE org_id = $1 AND id = $2`, orgID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAddonNotFound
	}
	return a, err
}

// GetClusterAddonByIDAnyOrg returns one addon by primary key regardless of
// org — the status-fold path keys off the agent-reported app name and
// authorizes via the reporting cluster, like the instance app-status path.
func (s *Store) GetClusterAddonByIDAnyOrg(ctx context.Context, q db.Querier, id string) (*types.ClusterAddon, error) {
	a, err := scanClusterAddon(q.QueryRow(ctx, `SELECT `+clusterAddonCols+`
		FROM cluster_addons WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAddonNotFound
	}
	return a, err
}

// UpsertDiscoveredAddon is the scanner-ingest variant: it inserts new rows
// as state=discovered and refreshes discovered_meta (+ the detected version)
// on existing DISCOVERED rows only. Managed/adopting/update_failed rows are
// owned by the adopt/update flow — discovery never overwrites them
// (plan §6: "never overwriting managed rows").
func (s *Store) UpsertDiscoveredAddon(ctx context.Context, q db.Querier, a *types.ClusterAddon) error {
	if a.ID == "" {
		a.ID = newULID()
	}
	source, err := json.Marshal(a.Source)
	if err != nil {
		return err
	}
	const sql = `INSERT INTO cluster_addons
		(id, org_id, cluster_id, catalog_item, state, deploy_mode, source, chart_version, discovered_meta)
		VALUES ($1,$2,$3,$4,'discovered','application',$5,$6,$7)
		ON CONFLICT (cluster_id, catalog_item) DO UPDATE SET
		  discovered_meta = EXCLUDED.discovered_meta,
		  chart_version = CASE WHEN EXCLUDED.chart_version = '' THEN cluster_addons.chart_version ELSE EXCLUDED.chart_version END,
		  updated_at = now()
		WHERE cluster_addons.state = 'discovered'`
	_, err = q.Exec(ctx, sql, a.ID, a.OrgID, a.ClusterID, a.CatalogItem, source, a.ChartVersion, a.DiscoveredMeta)
	return err
}

// SetClusterAddonPrune flips prune_enabled (the explicit human enable-prune
// action, decision 2). One-directional: there is no disable path yet.
func (s *Store) SetClusterAddonPrune(ctx context.Context, q db.Querier, orgID, id string) error {
	tag, err := q.Exec(ctx, `UPDATE cluster_addons SET prune_enabled = TRUE, updated_at = now()
		WHERE org_id = $1 AND id = $2`, orgID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrAddonNotFound
	}
	return nil
}

// SetClusterAddonState forces the row's lifecycle state (the update_failed
// flip must bypass UpsertClusterAddon's never-downgrade-managed guard).
func (s *Store) SetClusterAddonState(ctx context.Context, q db.Querier, orgID, id string, state types.AddonState) error {
	tag, err := q.Exec(ctx, `UPDATE cluster_addons SET state = $3, updated_at = now()
		WHERE org_id = $1 AND id = $2`, orgID, id, state)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrAddonNotFound
	}
	return nil
}

// ApplyAddonAppStatus folds an ArgoCD Application(/ApplicationSet) status
// into the addon row's health/sync columns.
func (s *Store) ApplyAddonAppStatus(ctx context.Context, q db.Querier, id, health, syncState string) error {
	tag, err := q.Exec(ctx, `UPDATE cluster_addons SET health = $2, sync = $3, updated_at = now()
		WHERE id = $1`, id, health, syncState)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrAddonNotFound
	}
	return nil
}

// BaselineRepoSelector resolves the repo selector an addon deploy should
// default to for one cluster: the cluster's bound baseline row, else the
// org's default repo row. "" means no registry row exists yet (callers map
// that to the no-git-config conflict, mirroring the orchestrator).
func (s *Store) BaselineRepoSelector(ctx context.Context, q db.Querier, orgID, clusterID string) (string, error) {
	var id *string
	err := q.QueryRow(ctx, `SELECT COALESCE(
		(SELECT baseline_repo_id FROM clusters WHERE org_id = $1 AND id = $2),
		(SELECT id FROM tenant_git_repos WHERE org_id = $1 AND is_default))`, orgID, clusterID).Scan(&id)
	if err != nil {
		return "", err
	}
	if id == nil {
		return "", nil
	}
	return *id, nil
}

// DeleteClusterAddon removes an addon row by id, scoped to the org.
func (s *Store) DeleteClusterAddon(ctx context.Context, q db.Querier, orgID, id string) error {
	tag, err := q.Exec(ctx, `DELETE FROM cluster_addons WHERE org_id = $1 AND id = $2`, orgID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrAddonNotFound
	}
	return nil
}
