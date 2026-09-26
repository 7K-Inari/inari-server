// Tenant deletion/decommission (ADR-0006): org-admin initiated,
// approval-gated, asynchronous teardown across Keycloak, OpenFGA, and
// PostgreSQL with audit retention. The state machine lives in
// tenant_deletions (migration 0020) and every step is idempotent so a
// failed or crashed run resumes at the failed step.
package tenancy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// ErrDeletionNotFound reports that no tenant_deletions row exists for an org.
var ErrDeletionNotFound = errors.New("tenant deletion not found")

// Dependency is one resource blocking tenant deletion.
type Dependency struct {
	Kind  string `json:"kind"` // cluster | instance | cloud_account | tenant_zone
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
}

// DependencyError rejects a non-forced deletion while blockers exist; the
// HTTP layer maps it to 409 with the structured list.
type DependencyError struct{ Blockers []Dependency }

func (e *DependencyError) Error() string {
	return fmt.Sprintf("tenant has %d blocking dependencies", len(e.Blockers))
}

// DeletionApprovalGate is the approvals.Service seam (defined here to avoid
// an import cycle: approvals imports tenancy for its HTTP TenantResolver).
type DeletionApprovalGate interface {
	RequestLifecycleApproval(ctx context.Context, orgID, action, requester string, context json.RawMessage) (approvalID string, err error)
}

// TupleStore is the OpenFGA seam for the synchronous tuple cleanup step.
type TupleStore interface {
	DeleteTuples(ctx context.Context, tuples []authz.Tuple) error
}

// ClusterRevoker is the clusterregistry.Service seam for the force path.
type ClusterRevoker interface {
	ListClusters(ctx context.Context, orgID string) ([]types.Cluster, error)
	RevokeCluster(ctx context.Context, actor, clusterID string) error
}

// ---------------------------------------------------------------------------
// Store: tenant_deletions persistence + snapshot/dependency queries
// ---------------------------------------------------------------------------

const tenantDeletionCols = `org_id, state, step, force, reason, requested_by, approval_id, snapshot, last_error, created_at, updated_at`

func (s *Store) scanTenantDeletion(row pgx.Row) (*types.TenantDeletion, error) {
	var d types.TenantDeletion
	err := row.Scan(&d.OrgID, &d.State, &d.Step, &d.Force, &d.Reason, &d.RequestedBy,
		&d.ApprovalID, &d.Snapshot, &d.LastError, &d.CreatedAt, &d.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDeletionNotFound
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (s *Store) CreateTenantDeletion(ctx context.Context, q db.Querier, d *types.TenantDeletion) error {
	const sql = `INSERT INTO tenant_deletions (` + tenantDeletionCols + `)
	             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, now(), now())
	             RETURNING created_at, updated_at`
	return q.QueryRow(ctx, sql, d.OrgID, d.State, d.Step, d.Force, d.Reason, d.RequestedBy,
		d.ApprovalID, d.Snapshot, d.LastError).Scan(&d.CreatedAt, &d.UpdatedAt)
}

func (s *Store) GetTenantDeletion(ctx context.Context, q db.Querier, orgID string) (*types.TenantDeletion, error) {
	const sql = `SELECT ` + tenantDeletionCols + ` FROM tenant_deletions WHERE org_id = $1`
	return s.scanTenantDeletion(q.QueryRow(ctx, sql, orgID))
}

func (s *Store) SetTenantDeletionApproval(ctx context.Context, q db.Querier, orgID, approvalID string) error {
	const sql = `UPDATE tenant_deletions SET approval_id = $2, updated_at = now() WHERE org_id = $1`
	_, err := q.Exec(ctx, sql, orgID, approvalID)
	return err
}

// UpdateTenantDeletion records progress (step), failure state, or a retry
// reset in one write.
func (s *Store) UpdateTenantDeletion(ctx context.Context, q db.Querier, orgID, state, step, lastError string) error {
	const sql = `UPDATE tenant_deletions SET state = $2, step = $3, last_error = $4, updated_at = now() WHERE org_id = $1`
	_, err := q.Exec(ctx, sql, orgID, state, step, lastError)
	return err
}

// DeleteTenantDeletionRow removes the tracking row (approval denied path;
// the row also cascades away with the organization on successful teardown).
func (s *Store) DeleteTenantDeletionRow(ctx context.Context, q db.Querier, orgID string) error {
	const sql = `DELETE FROM tenant_deletions WHERE org_id = $1`
	_, err := q.Exec(ctx, sql, orgID)
	return err
}

// ListPendingTenantDeletions returns in-flight and failed deletions for the
// startup resume scan. Rows still awaiting their approval decision are
// excluded: an undecided decommission must never run (the scan fires on
// every boot/lease failover, long before any human decides).
func (s *Store) ListPendingTenantDeletions(ctx context.Context, q db.Querier) ([]types.TenantDeletion, error) {
	const sql = `SELECT ` + tenantDeletionCols + ` FROM tenant_deletions WHERE state IN ($1, $2) ORDER BY created_at`
	rows, err := q.Query(ctx, sql, types.TenantDeletionStateDeleting, types.TenantDeletionStateFailed)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.TenantDeletion
	for rows.Next() {
		d, err := s.scanTenantDeletion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// ListDeletionBlockers enumerates resources that must be torn down before
// the tenant can go: non-terminal clusters, in-flight instances, registered
// cloud accounts, and non-closed tenant zones.
func (s *Store) ListDeletionBlockers(ctx context.Context, q db.Querier, orgID string) ([]Dependency, error) {
	var out []Dependency
	queries := []struct {
		kind string
		sql  string
	}{
		{"cluster", `SELECT id, name, state FROM clusters
		              WHERE org_id = $1 AND state NOT IN ('decommissioned','revoked') ORDER BY id`},
		{"instance", `SELECT id, catalog_item_id, state::text FROM resource_instances
		               WHERE org_id = $1 AND state IN ('pending','deploying','deleting') ORDER BY id`},
		{"cloud_account", `SELECT id, account_id, state FROM cloud_accounts WHERE org_id = $1 ORDER BY id`},
		{"tenant_zone", `SELECT id, slug, state FROM tenant_zones
		                  WHERE org_id = $1 AND state <> 'closed' ORDER BY id`},
	}
	for _, qq := range queries {
		rows, err := q.Query(ctx, qq.sql, orgID)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var dep Dependency
			if err := rows.Scan(&dep.ID, &dep.Name, &dep.State); err != nil {
				rows.Close()
				return nil, err
			}
			dep.Kind = qq.kind
			out = append(out, dep)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// tenantSnapshot builds the TenantDeletingPayload: the full set of OpenFGA
// tuples the teardown must retract. Enumerated from the DB (deterministic,
// no FGA Reads) at request time and stored on the tenant_deletions row so
// retries work even after partial teardown.
func (s *Store) tenantSnapshot(ctx context.Context, q db.Querier, org *types.Organization) (*types.TenantDeletingPayload, error) {
	p := &types.TenantDeletingPayload{OrgID: org.ID, Slug: org.Slug, Objects: map[string][]string{}}
	teams, err := s.ListTeams(ctx, q, org.ID)
	if err != nil {
		return nil, err
	}
	for _, t := range teams {
		p.Teams = append(p.Teams, types.TeamSeed{TeamID: t.ID, Name: t.Name, Role: t.Role})
	}
	mrows, err := q.Query(ctx, `SELECT user_id, team_id, role FROM memberships WHERE org_id = $1 AND team_id IS NOT NULL`, org.ID)
	if err != nil {
		return nil, err
	}
	defer mrows.Close()
	for mrows.Next() {
		var m types.MembershipPayload
		if err := mrows.Scan(&m.UserID, &m.TeamID, &m.Role); err != nil {
			return nil, err
		}
		m.OrgID = org.ID
		p.Members = append(p.Members, m)
	}
	if err := mrows.Err(); err != nil {
		return nil, err
	}
	objects := []struct {
		fgaType string
		sql     string
	}{
		{"cluster", `SELECT id FROM clusters WHERE org_id = $1`},
		{"cloud_account", `SELECT id FROM cloud_accounts WHERE org_id = $1`},
		{"cluster_set", `SELECT id FROM cluster_sets WHERE org_id = $1`},
		{"policy_pack", `SELECT id FROM policy_packs WHERE org_id = $1`},
		{"extension", `SELECT id FROM extensions WHERE org_id = $1`},
		{"rollout", `SELECT id FROM rollouts WHERE org_id = $1`},
		{"drift_event", `SELECT id FROM drift_events WHERE org_id = $1`},
		{"tenant_zone", `SELECT id FROM tenant_zones WHERE org_id = $1`},
	}
	for _, o := range objects {
		rows, err := q.Query(ctx, o.sql, org.ID)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, err
			}
			p.Objects[o.fgaType] = append(p.Objects[o.fgaType], id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// ---------------------------------------------------------------------------
// Service: request gate
// ---------------------------------------------------------------------------

// DeleteTenant validates blockers, freezes the org (status=deleting), and
// opens a platform-admin lifecycle approval (tenant.decommission). The
// teardown runs when the approval is decided (DeletionResumeHandler).
// Returns the approval id; re-requesting while a deletion is pending is
// idempotent and returns the existing approval id.
func (s *Service) DeleteTenant(ctx context.Context, actor, slug string, force bool, reason string) (string, error) {
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return "", err
	}
	if org.Status == types.OrgStatusDeleting {
		if del, derr := s.store.GetTenantDeletion(ctx, s.db.Pool, org.ID); derr == nil {
			return del.ApprovalID, nil // idempotent re-request
		}
	}
	blockers, err := s.store.ListDeletionBlockers(ctx, s.db.Pool, org.ID)
	if err != nil {
		return "", err
	}
	if len(blockers) > 0 && !force {
		return "", &DependencyError{Blockers: blockers}
	}
	snapshot, err := s.store.tenantSnapshot(ctx, s.db.Pool, org)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return "", err
	}
	del := &types.TenantDeletion{
		OrgID: org.ID, State: types.TenantDeletionStateAwaitingApproval,
		Force: force, Reason: reason, RequestedBy: actor, Snapshot: raw,
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.SetOrgStatus(ctx, tx, org.ID, types.OrgStatusDeleting); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: org.ID, Actor: actor, Action: "tenant.decommission_requested",
			ObjectType: "organization", ObjectID: org.ID,
			Payload: []byte(fmt.Sprintf(`{"force":%t,"reason":%q}`, force, reason)),
		}); err != nil {
			return err
		}
		if err := s.store.CreateTenantDeletion(ctx, tx, del); err != nil {
			return err
		}
		// Defensive second sweep for FGA cleanup listeners; the Deleter
		// also retracts the tuples synchronously as its own step.
		return audit.AppendOutbox(ctx, tx, org.ID, types.EventTenantDeleting, snapshot)
	})
	if err != nil {
		return "", err
	}
	// The org is now frozen (status=deleting): evict the cached row so
	// ensureOrgActive rejects mutations immediately, not after cache TTL.
	s.invalidateOrgCache(ctx, slug)
	if s.gate == nil {
		return "", errors.New("tenancy: deletion approval gate not wired")
	}
	approvalCtx, _ := json.Marshal(struct {
		OrgID  string `json:"orgId"`
		Slug   string `json:"slug"`
		Force  bool   `json:"force"`
		Reason string `json:"reason,omitempty"`
	}{OrgID: org.ID, Slug: slug, Force: force, Reason: reason})
	approvalID, err := s.gate.RequestLifecycleApproval(ctx, org.ID, types.ApprovalActionTenantDecommission, actor, approvalCtx)
	if err != nil {
		return "", err
	}
	if err := s.store.SetTenantDeletionApproval(ctx, s.db.Pool, org.ID, approvalID); err != nil {
		return "", err
	}
	return approvalID, nil
}

// GetDeletion returns the deletion progress for an org.
func (s *Service) GetDeletion(ctx context.Context, slug string) (*types.TenantDeletion, error) {
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return nil, err
	}
	return s.store.GetTenantDeletion(ctx, s.db.Pool, org.ID)
}

// DeletionDependencies dry-runs the blocker check without starting anything.
func (s *Service) DeletionDependencies(ctx context.Context, slug string) ([]Dependency, error) {
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return nil, err
	}
	return s.store.ListDeletionBlockers(ctx, s.db.Pool, org.ID)
}

// RetryDeletion resets a failed deletion to deleting and re-runs the
// teardown synchronously (the runner resumes at the failed step).
func (s *Service) RetryDeletion(ctx context.Context, slug string) (*types.TenantDeletion, error) {
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return nil, err
	}
	del, err := s.store.GetTenantDeletion(ctx, s.db.Pool, org.ID)
	if err != nil {
		return nil, err
	}
	if del.State != types.TenantDeletionStateFailed {
		return nil, fmt.Errorf("tenancy: deletion for %s is %s, not failed", slug, del.State)
	}
	if err := s.store.UpdateTenantDeletion(ctx, s.db.Pool, org.ID, types.TenantDeletionStateDeleting, del.Step, ""); err != nil {
		return nil, err
	}
	if s.deleter == nil {
		return nil, errors.New("tenancy: deleter not wired")
	}
	if err := s.deleter.Run(ctx, org.ID); err != nil {
		return nil, err
	}
	del, err = s.store.GetTenantDeletion(ctx, s.db.Pool, org.ID)
	if errors.Is(err, ErrDeletionNotFound) {
		// Teardown completed: the tracking row cascaded away with the org.
		return &types.TenantDeletion{OrgID: org.ID, State: types.OrgStatusDeleted}, nil
	}
	return del, err
}

// ---------------------------------------------------------------------------
// Deleter: ordered, resumable teardown state machine
// ---------------------------------------------------------------------------

// Teardown steps in execution order. tenant_deletions.step records the last
// completed step; the runner executes everything after it.
var deletionSteps = []string{
	"revoke_clusters",
	"archive_audit",
	"fga_cleanup",
	"delete_keycloak_org",
	"delete_org_row",
}

// Deleter runs the tenant teardown state machine. FGA tuple cleanup is a
// synchronous step (not fire-and-forget via outbox) so a failure surfaces in
// tenant_deletions.last_error instead of silently dead-lettering.
type Deleter struct {
	db       *db.DB
	idp      IdentityProvider
	store    *Store
	audit    *audit.Store
	fga      TupleStore
	clusters ClusterRevoker
	log      *slog.Logger
	orgCache *OrgCache
}

// WithOrgCache wires the slug→org cache so the teardown can evict the org
// row it deletes (ADR-0010). Fail-open; optional.
func (d *Deleter) WithOrgCache(c *OrgCache) *Deleter {
	d.orgCache = c
	return d
}

func NewDeleter(d *db.DB, idp IdentityProvider, store *Store, auditStore *audit.Store, fga TupleStore, clusters ClusterRevoker, log *slog.Logger) *Deleter {
	if log == nil {
		log = slog.Default()
	}
	return &Deleter{db: d, idp: idp, store: store, audit: auditStore, fga: fga, clusters: clusters, log: log}
}

// Run executes the remaining teardown steps for an org. Re-entrant: it
// resumes after tenant_deletions.step. A step failure flips the row to
// delete_failed with last_error; retry (or the startup scan) resumes.
// Defense in depth: Run refuses rows still awaiting their approval
// decision — only the approval-decided handler may transition a row out of
// awaiting_approval before running the teardown.
func (d *Deleter) Run(ctx context.Context, orgID string) error {
	del, err := d.store.GetTenantDeletion(ctx, d.db.Pool, orgID)
	if errors.Is(err, ErrDeletionNotFound) {
		return nil // already torn down (row cascaded with the org)
	}
	if err != nil {
		return err
	}
	if del.State == types.TenantDeletionStateAwaitingApproval {
		return fmt.Errorf("tenancy: deletion for %s is still awaiting approval; refusing to run", orgID)
	}
	start := 0
	for i, s := range deletionSteps {
		if s == del.Step {
			start = i + 1
		}
	}
	for i := start; i < len(deletionSteps); i++ {
		step := deletionSteps[i]
		if err := d.runStep(ctx, step, del); err != nil {
			_ = d.store.UpdateTenantDeletion(ctx, d.db.Pool, orgID, types.TenantDeletionStateFailed, del.Step, err.Error())
			return fmt.Errorf("tenancy: deletion step %s: %w", step, err)
		}
		del.Step = step
	}
	return nil
}

// ResumePendingDeletions re-runs every in-flight or failed deletion (the
// dispatcher has no startup-resume hook, so crashed teardowns are picked up
// here on boot).
func (d *Deleter) ResumePendingDeletions(ctx context.Context) {
	pending, err := d.store.ListPendingTenantDeletions(ctx, d.db.Pool)
	if err != nil {
		d.log.Error("tenant deletion resume: list pending", "error", err)
		return
	}
	for _, del := range pending {
		if err := d.Run(ctx, del.OrgID); err != nil {
			d.log.Error("tenant deletion resume failed", "org", del.OrgID, "error", err)
		}
	}
}

func (d *Deleter) runStep(ctx context.Context, step string, del *types.TenantDeletion) error {
	switch step {
	case "revoke_clusters":
		return d.stepRevokeClusters(ctx, del)
	case "archive_audit":
		return d.stepArchiveAudit(ctx, del)
	case "fga_cleanup":
		return d.stepFGACleanup(ctx, del)
	case "delete_keycloak_org":
		return d.stepDeleteKeycloakOrg(ctx, del)
	case "delete_org_row":
		return d.stepDeleteOrgRow(ctx, del)
	}
	return fmt.Errorf("unknown step %q", step)
}

// markDone records a completed step in its own transaction.
func (d *Deleter) markDone(ctx context.Context, q db.Querier, orgID, step string) error {
	return d.store.UpdateTenantDeletion(ctx, q, orgID, types.TenantDeletionStateDeleting, step, "")
}

func (d *Deleter) stepRevokeClusters(ctx context.Context, del *types.TenantDeletion) error {
	if del.Force && d.clusters != nil {
		clusters, err := d.clusters.ListClusters(ctx, del.OrgID)
		if err != nil {
			return err
		}
		for _, c := range clusters {
			if c.State == types.ClusterStateDecommissioned || c.State == types.ClusterStateRevoked {
				continue
			}
			// Emits the existing cluster.revoked outbox event so agents and
			// the tuple writer reconcile.
			if err := d.clusters.RevokeCluster(ctx, "system:tenant-deletion", c.ID); err != nil {
				return fmt.Errorf("revoke cluster %s: %w", c.ID, err)
			}
		}
	}
	return d.markDone(ctx, d.db.Pool, del.OrgID, "revoke_clusters")
}

// stepArchiveAudit moves the org's audit rows to audit_archive and purges
// its outbox rows (published and pending) so the dispatcher never replays
// events for a dead org. The GUC gate keeps audit_events append-only for
// everyone else; pgx SET LOCAL is transaction-scoped, so pooling is safe.
func (d *Deleter) stepArchiveAudit(ctx context.Context, del *types.TenantDeletion) error {
	return d.db.WithTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL audit.allow_delete = 'on'`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO audit_archive SELECT *, now() FROM audit_events WHERE org_id = $1
			 ON CONFLICT (id) DO NOTHING`, del.OrgID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM audit_events WHERE org_id = $1`, del.OrgID); err != nil {
			return err
		}
		// Only published rows: this step usually runs inside the dispatcher's
		// own batch transaction (driven by the org's approval.decided event),
		// which still holds FOR-UPDATE locks on its unpublished rows — deleting
		// those self-locks the runner and stalls the teardown at this step
		// (live finding, 2026-09-13). Leftover pending rows for the dead org
		// fail their handlers and dead-letter out instead.
		if _, err := tx.Exec(ctx, `DELETE FROM outbox WHERE org_id = $1 AND published_at IS NOT NULL`, del.OrgID); err != nil {
			return err
		}
		return d.markDone(ctx, tx, del.OrgID, "archive_audit")
	})
}

// stepFGACleanup synchronously retracts every tuple in the snapshot. FGA
// deletes are idempotent (absent tuples are ignored), so retries are safe.
func (d *Deleter) stepFGACleanup(ctx context.Context, del *types.TenantDeletion) error {
	var p types.TenantDeletingPayload
	if err := json.Unmarshal(del.Snapshot, &p); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	tuples, err := authz.TuplesForTenantDeletion(&p)
	if err != nil {
		return err
	}
	if len(tuples) > 0 {
		if err := d.fga.DeleteTuples(ctx, tuples); err != nil {
			return err
		}
	}
	return d.markDone(ctx, d.db.Pool, del.OrgID, "fga_cleanup")
}

// stepDeleteKeycloakOrg removes the Keycloak organization and the tenant's
// realm group tree (tenant-<slug>/...). Group deletion is 404-tolerant, so
// orgs/groups removed manually Keycloak-side are treated as done (drift
// tolerance). NOTE: KC organization deletion does NOT cascade to realm
// groups — without the explicit group-tree delete they orphan (observed
// live: tenant-e2e-del3/del4 groups left behind).
func (d *Deleter) stepDeleteKeycloakOrg(ctx context.Context, del *types.TenantDeletion) error {
	org, err := d.store.GetOrganizationByID(ctx, d.db.Pool, del.OrgID)
	if err != nil {
		return err
	}
	if err := d.idp.DeleteOrganization(ctx, org.KeycloakOrgID); err != nil {
		return err
	}
	if err := d.idp.DeleteGroup(ctx, "tenant-"+org.Slug); err != nil {
		return fmt.Errorf("delete group tree tenant-%s: %w", org.Slug, err)
	}
	return d.markDone(ctx, d.db.Pool, del.OrgID, "delete_keycloak_org")
}

// stepDeleteOrgRow removes the org row. FK-cascading children (teams,
// memberships, clusters, instances, catalog visibility/pins, approvals,
// policies, policy_packs, cluster_sets, exemptions, notifications,
// cloud_accounts, extensions, rollouts, drift_events, identity_clients,
// idp_brokers, platform_resources) go with it; the tables without an
// organizations FK (secret_stores, scaffold_runs, tenant_zones,
// approval_config) are deleted explicitly first. The final audit row keeps
// the org id string (audit_events has no FK) for traceability, and
// tenant.deleted notifies any future listeners.
func (d *Deleter) stepDeleteOrgRow(ctx context.Context, del *types.TenantDeletion) error {
	err := d.db.WithTx(ctx, func(tx pgx.Tx) error {
		for _, table := range []string{"secret_stores", "scaffold_runs", "tenant_zones", "approval_config"} {
			if _, err := tx.Exec(ctx, fmt.Sprintf(`DELETE FROM %s WHERE org_id = $1`, table), del.OrgID); err != nil {
				return err
			}
		}
		if err := d.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: del.OrgID, Actor: "system:tenant-deletion", Action: "tenant.deleted",
			ObjectType: "organization", ObjectID: del.OrgID,
			Payload: []byte(fmt.Sprintf(`{"requestedBy":%q,"force":%t}`, del.RequestedBy, del.Force)),
		}); err != nil {
			return err
		}
		if err := audit.AppendOutbox(ctx, tx, del.OrgID, types.EventTenantDeleted, types.TenantDeletedPayload{
			OrgID: del.OrgID, Slug: slugFromSnapshot(del.Snapshot),
		}); err != nil {
			return err
		}
		return d.store.DeleteOrganization(ctx, tx, del.OrgID)
	})
	if err == nil && d.orgCache != nil {
		// The org row is gone: never serve it from cache again.
		d.orgCache.Invalidate(ctx, slugFromSnapshot(del.Snapshot))
	}
	return err
}

func slugFromSnapshot(raw json.RawMessage) string {
	var p types.TenantDeletingPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return ""
	}
	return p.Slug
}

// MarkDeletionApproved transitions a deletion out of awaiting_approval so
// the teardown may run. Only the approval-decided handler may call it.
func (s *Service) MarkDeletionApproved(ctx context.Context, orgID string) error {
	return s.store.UpdateTenantDeletion(ctx, s.db.Pool, orgID, types.TenantDeletionStateDeleting, "", "")
}

// denyDeletion restores an org whose decommission approval was rejected.
func (s *Service) denyDeletion(ctx context.Context, orgID, approvalID string) error {
	return s.restoreOrg(ctx, orgID, approvalID, "tenant.decommission_denied")
}

// abortDeletion restores an org whose decommission approval was withdrawn
// by the requester.
func (s *Service) abortDeletion(ctx context.Context, orgID, approvalID string) error {
	return s.restoreOrg(ctx, orgID, approvalID, "tenant.decommission_cancelled")
}

// restoreOrg returns an org whose decommission was denied or cancelled to
// active: status restored, tracking row removed, restore audited, and a
// tenant.restored outbox event carrying the freeze-time snapshot so the
// tuple writer re-seeds the FGA tuples swept at request time (without it
// the org comes back active but every org-scoped FGA check keeps failing).
func (s *Service) restoreOrg(ctx context.Context, orgID, approvalID, action string) error {
	var snapshot json.RawMessage
	if del, err := s.store.GetTenantDeletion(ctx, s.db.Pool, orgID); err == nil {
		snapshot = del.Snapshot
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.SetOrgStatus(ctx, tx, orgID, types.OrgStatusActive); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: "system:approvals", Action: action,
			ObjectType: "organization", ObjectID: orgID,
			Payload: []byte(fmt.Sprintf(`{"approvalId":%q}`, approvalID)),
		}); err != nil {
			return err
		}
		if err := s.store.DeleteTenantDeletionRow(ctx, tx, orgID); err != nil {
			return err
		}
		if len(snapshot) == 0 {
			return nil
		}
		var p types.TenantDeletingPayload
		if err := json.Unmarshal(snapshot, &p); err != nil {
			return fmt.Errorf("tenancy: restore org: snapshot: %w", err)
		}
		if err := audit.AppendOutbox(ctx, tx, orgID, types.EventTenantRestored, &p); err != nil {
			return err
		}
		// Status flipped back to active: evict the frozen row from cache.
		s.invalidateOrgCache(ctx, p.Slug)
		return nil
	})
}
