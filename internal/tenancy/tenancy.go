// Package tenancy implements the Tenancy & Identity module: tenant lifecycle
// backed by Keycloak Organizations, teams as groups tenant-<slug>/<team>,
// and DB projection with audit + outbox writes.
package tenancy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// IdentityProvider abstracts the Keycloak Admin API.
type IdentityProvider interface {
	CreateOrganization(ctx context.Context, alias, displayName string) (kcOrgID string, err error)
	UpdateOrganization(ctx context.Context, kcOrgID, displayName string) error
	DeleteOrganization(ctx context.Context, kcOrgID string) error
	CreateGroup(ctx context.Context, path string) (groupID string, err error)
	DeleteGroup(ctx context.Context, path string) error
	// ListOrganizations returns the aliases of orgs the user is a member of.
	ListOrganizations(ctx context.Context, userID string) ([]string, error)
	AddOrganizationMember(ctx context.Context, kcOrgID, userID string) error
	RemoveOrganizationMember(ctx context.Context, kcOrgID, userID string) error
	AddGroupMember(ctx context.Context, groupPath, userID string) error
	RemoveGroupMember(ctx context.Context, groupPath, userID string) error
	// ListGroupMembers returns the Keycloak user ids in the group at the path.
	ListGroupMembers(ctx context.Context, groupPath string) ([]string, error)
	GetUser(ctx context.Context, userID string) (*types.User, error)
	// GetUserByEmail resolves a realm user by exact email match (member
	// management accepts an email in place of a Keycloak UUID).
	GetUserByEmail(ctx context.Context, email string) (*types.User, error)
}

// DefaultTeams are created with every tenant, each bound to a built-in
// role. org-admins is the anchor team for the tenant's first administrator
// — without it no one could ever reach the admin role (every admin-granting
// route is admin gated, and the deletion/RBAC routes require it), which the
// live e2e run proved makes tenants unmanageable.
var DefaultTeams = []struct {
	Name     string
	RoleName string
}{
	{OrgAdminsTeamName, authz.BuiltinRoleAdmin},
	{PlatformTeamName, authz.BuiltinRoleOperator},
	{DevelopersTeamName, authz.BuiltinRoleEditor},
	{ViewersTeamName, authz.BuiltinRoleViewer},
}

var (
	ErrSlugTaken     = errors.New("tenant slug already exists")
	ErrOrgNotFound   = errors.New("organization not found")
	ErrUserNotFound  = errors.New("user not found")
	ErrTeamNotFound  = errors.New("team not found")
	ErrTeamNameTaken = errors.New("team name already exists in tenant")
	ErrDefaultTeam   = errors.New("default teams cannot be modified")
	// ErrMembersTeamInUse rejects deleting the "members" team while a
	// brokered IdP exists: its Hardcoded Group mapper targets the team's
	// Keycloak group, so deletion would break brokered logins (ADR-0004).
	ErrMembersTeamInUse = errors.New("members team is required by the brokered identity provider")
)

// PlatformTeamName is the default team that receives the tenant creator.
const PlatformTeamName = "platform-team"

// OrgAdminsTeamName is the anchor team granting the admin role; it is also
// created with every tenant and receives the tenant creator so the first
// administrator exists without a circular admin-gated grant.
const OrgAdminsTeamName = "org-admins"

// DevelopersTeamName and ViewersTeamName are the remaining built-in anchor
// teams (editor and viewer bundles).
const (
	DevelopersTeamName = "developers"
	ViewersTeamName    = "viewers"
)

// builtinAnchorTeam maps a built-in role name onto its anchor team. Anchor
// teams are protected from rename/delete (ErrDefaultTeam); a custom role's
// anchor is a team named after the role (materialized lazily on first
// SetMemberRole).
var builtinAnchorTeam = map[string]string{
	authz.BuiltinRoleAdmin:    OrgAdminsTeamName,
	authz.BuiltinRoleOperator: PlatformTeamName,
	authz.BuiltinRoleEditor:   DevelopersTeamName,
	authz.BuiltinRoleViewer:   ViewersTeamName,
}

// AnchorTeamForRole returns the name of the team granting the role.
func AnchorTeamForRole(r *types.Role) string {
	if r.Builtin {
		if name, ok := builtinAnchorTeam[r.Name]; ok {
			return name
		}
	}
	return r.Name
}

// membersTeamName is the team materialized for a brokered IdP's Hardcoded
// Group mapper target (tenant-<slug>/members), granting org viewer.
const membersTeamName = "members"

// Store is the PostgreSQL projection of tenancy state.
type Store struct{}

func NewStore() *Store { return &Store{} }

func (s *Store) CreateOrganization(ctx context.Context, q db.Querier, org *types.Organization) error {
	const sql = `INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ($1,$2,$3,$4) RETURNING status, created_at`
	err := q.QueryRow(ctx, sql, org.ID, org.Slug, org.DisplayName, org.KeycloakOrgID).Scan(&org.Status, &org.CreatedAt)
	if isUniqueViolation(err) {
		return ErrSlugTaken
	}
	return err
}

func (s *Store) GetOrganizationBySlug(ctx context.Context, q db.Querier, slug string) (*types.Organization, error) {
	const sql = `SELECT id, slug, display_name, keycloak_org_id, status, created_at FROM organizations WHERE slug = $1`
	var org types.Organization
	err := q.QueryRow(ctx, sql, slug).Scan(&org.ID, &org.Slug, &org.DisplayName, &org.KeycloakOrgID, &org.Status, &org.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrOrgNotFound
	}
	if err != nil {
		return nil, err
	}
	return &org, nil
}

func (s *Store) GetOrganizationByID(ctx context.Context, q db.Querier, id string) (*types.Organization, error) {
	const sql = `SELECT id, slug, display_name, keycloak_org_id, status, created_at FROM organizations WHERE id = $1`
	var org types.Organization
	err := q.QueryRow(ctx, sql, id).Scan(&org.ID, &org.Slug, &org.DisplayName, &org.KeycloakOrgID, &org.Status, &org.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrOrgNotFound
	}
	if err != nil {
		return nil, err
	}
	return &org, nil
}

// SetOrgStatus flips the organization lifecycle status (ADR-0006).
func (s *Store) SetOrgStatus(ctx context.Context, q db.Querier, orgID, status string) error {
	const sql = `UPDATE organizations SET status = $2 WHERE id = $1`
	_, err := q.Exec(ctx, sql, orgID, status)
	return err
}

// DeleteOrganization removes the org row; FK-cascading children go with it.
// Tables without an organizations FK (secret_stores, scaffold_runs,
// tenant_zones, approval_config) must be deleted explicitly first — see the
// tenant deleter.
func (s *Store) DeleteOrganization(ctx context.Context, q db.Querier, orgID string) error {
	const sql = `DELETE FROM organizations WHERE id = $1`
	_, err := q.Exec(ctx, sql, orgID)
	return err
}

func (s *Store) ListOrganizations(ctx context.Context, q db.Querier) ([]types.Organization, error) {
	const sql = `SELECT id, slug, display_name, keycloak_org_id, status, created_at FROM organizations ORDER BY created_at`
	rows, err := q.Query(ctx, sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Organization
	for rows.Next() {
		var o types.Organization
		if err := rows.Scan(&o.ID, &o.Slug, &o.DisplayName, &o.KeycloakOrgID, &o.Status, &o.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) CreateTeam(ctx context.Context, q db.Querier, team *types.Team) error {
	const sql = `INSERT INTO teams (org_id, name, role_id, keycloak_group_path) VALUES ($1,$2,$3,$4) RETURNING id, created_at`
	err := q.QueryRow(ctx, sql, team.OrgID, team.Name, team.RoleID, team.KeycloakGroupPath).Scan(&team.ID, &team.CreatedAt)
	if isUniqueViolation(err) {
		return ErrTeamNameTaken
	}
	return err
}

// UpdateOrganizationDisplayName updates the org profile projection.
func (s *Store) UpdateOrganizationDisplayName(ctx context.Context, q db.Querier, orgID, displayName string) error {
	const sql = `UPDATE organizations SET display_name = $2 WHERE id = $1`
	_, err := q.Exec(ctx, sql, orgID, displayName)
	return err
}

// teamColumns is the team projection with the role name joined in (views
// and ClusterRole naming consume RoleName; FK writes use RoleID).
const teamColumns = `t.id, t.org_id, t.name, t.display_name, t.role_id, r.name, t.keycloak_group_path, t.created_at`

const teamJoin = ` FROM teams t JOIN roles r ON r.id = t.role_id`

// UpdateTeamDisplayName updates a team's mutable display name and returns
// the updated record (name and keycloak_group_path are immutable, ADR-0007).
func (s *Store) UpdateTeamDisplayName(ctx context.Context, q db.Querier, orgID, name, displayName string) (*types.Team, error) {
	const sql = `UPDATE teams SET display_name = $3 WHERE org_id = $1 AND name = $2
	             RETURNING id, org_id, name, display_name, role_id, keycloak_group_path, created_at`
	var t types.Team
	err := q.QueryRow(ctx, sql, orgID, name, displayName).
		Scan(&t.ID, &t.OrgID, &t.Name, &t.DisplayName, &t.RoleID, &t.KeycloakGroupPath, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTeamNotFound
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// DeleteTeam removes a team row and returns the deleted record for audit
// payloads; membership rows cascade away via FK.
func (s *Store) DeleteTeam(ctx context.Context, q db.Querier, orgID, name string) (*types.Team, error) {
	const sql = `DELETE FROM teams WHERE org_id = $1 AND name = $2
	             RETURNING id, org_id, name, display_name, role_id, keycloak_group_path, created_at`
	var t types.Team
	err := q.QueryRow(ctx, sql, orgID, name).Scan(&t.ID, &t.OrgID, &t.Name, &t.DisplayName, &t.RoleID, &t.KeycloakGroupPath, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTeamNotFound
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) ListTeams(ctx context.Context, q db.Querier, orgID string) ([]types.Team, error) {
	const sql = `SELECT ` + teamColumns + teamJoin + ` WHERE t.org_id = $1 ORDER BY t.name`
	return s.scanTeams(ctx, q, sql, orgID)
}

// ListAllTeams returns every team across all orgs (the authz org-team
// reconciler enumerates team groups without an org scope).
func (s *Store) ListAllTeams(ctx context.Context, q db.Querier) ([]types.Team, error) {
	const sql = `SELECT ` + teamColumns + teamJoin + ` ORDER BY t.org_id, t.name`
	return s.scanTeams(ctx, q, sql)
}

// ListActiveTeams returns teams of active orgs only — the OrgTeamSync seam.
// Teams of a deleting tenant are excluded so the reconciler cannot
// resurrect tuples the teardown is retracting (ADR-0006).
func (s *Store) ListActiveTeams(ctx context.Context, q db.Querier) ([]types.Team, error) {
	const sql = `SELECT ` + teamColumns + teamJoin + ` JOIN organizations o ON o.id = t.org_id
	             WHERE o.status = 'active' ORDER BY t.org_id, t.name`
	return s.scanTeams(ctx, q, sql)
}

func (s *Store) scanTeams(ctx context.Context, q db.Querier, sql string, args ...any) ([]types.Team, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Team
	for rows.Next() {
		var t types.Team
		if err := rows.Scan(&t.ID, &t.OrgID, &t.Name, &t.DisplayName, &t.RoleID, &t.RoleName, &t.KeycloakGroupPath, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) UpsertUser(ctx context.Context, q db.Querier, u *types.User) error {
	// Empty fields in the incoming profile (e.g. a Keycloak group-member
	// payload the IdP did not map an email onto) never erase values an
	// earlier writer stored.
	const sql = `INSERT INTO users (id, email, display_name) VALUES ($1,$2,$3)
	             ON CONFLICT (id) DO UPDATE SET
	               email = COALESCE(NULLIF(EXCLUDED.email, ''), users.email),
	               display_name = COALESCE(NULLIF(EXCLUDED.display_name, ''), users.display_name)`
	_, err := q.Exec(ctx, sql, u.ID, u.Email, u.DisplayName)
	return err
}

// AddMembership inserts a membership row, reporting whether a row was
// actually inserted (false on conflict). Callers use the flag to emit
// outbox events exactly once even under concurrent adds.
func (s *Store) AddMembership(ctx context.Context, q db.Querier, m *types.Membership) (bool, error) {
	const sql = `INSERT INTO memberships (user_id, org_id, team_id, role_id) VALUES ($1,$2,$3,$4)
	             ON CONFLICT (user_id, org_id, role_id) DO NOTHING`
	var teamID *string
	if m.TeamID != "" {
		teamID = &m.TeamID
	}
	tag, err := q.Exec(ctx, sql, m.UserID, m.OrgID, teamID, m.RoleID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// RemoveMembership deletes a user's team membership row, reporting whether
// a row was actually deleted (drives exactly-once outbox emission).
func (s *Store) RemoveMembership(ctx context.Context, q db.Querier, m *types.Membership) (bool, error) {
	const sql = `DELETE FROM memberships WHERE user_id = $1 AND org_id = $2 AND team_id = $3`
	tag, err := q.Exec(ctx, sql, m.UserID, m.OrgID, m.TeamID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// MembershipWithPath joins a membership row with its team's Keycloak group
// path (used to undo Keycloak group joins on removal).
type MembershipWithPath struct {
	TeamID    string
	GroupPath string
	RoleID    string
}

// ListMembershipsWithPaths returns all of a user's memberships in an org
// with the group's Keycloak path.
func (s *Store) ListMembershipsWithPaths(ctx context.Context, q db.Querier, orgID, userID string) ([]MembershipWithPath, error) {
	const sql = `SELECT m.team_id, COALESCE(t.keycloak_group_path,''), m.role_id
	             FROM memberships m LEFT JOIN teams t ON t.id = m.team_id
	             WHERE m.org_id = $1 AND m.user_id = $2`
	rows, err := q.Query(ctx, sql, orgID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MembershipWithPath
	for rows.Next() {
		var mp MembershipWithPath
		var teamID *string
		if err := rows.Scan(&teamID, &mp.GroupPath, &mp.RoleID); err != nil {
			return nil, err
		}
		if teamID != nil {
			mp.TeamID = *teamID
		}
		out = append(out, mp)
	}
	return out, rows.Err()
}

// RemoveMembershipsForUser deletes all of a user's membership rows in an
// org, returning the removed rows so exactly one outbox event is emitted
// per removed tuple.
func (s *Store) RemoveMembershipsForUser(ctx context.Context, q db.Querier, orgID, userID string) ([]types.Membership, error) {
	const sql = `DELETE FROM memberships WHERE org_id = $1 AND user_id = $2 RETURNING team_id, role_id`
	rows, err := q.Query(ctx, sql, orgID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Membership
	for rows.Next() {
		var m types.Membership
		var teamID *string
		if err := rows.Scan(&teamID, &m.RoleID); err != nil {
			return nil, err
		}
		m.OrgID = orgID
		m.UserID = userID
		if teamID != nil {
			m.TeamID = *teamID
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// OrgMemberView is the org-wide console view of a user: profile, the roles
// they hold (custom roles have no total order, so this is a sorted set, not
// a "highest" role), and the teams they belong to.
type OrgMemberView struct {
	UserID      string   `json:"userId"`
	Email       string   `json:"email"`
	DisplayName string   `json:"displayName"`
	Roles       []string `json:"roles"`
	Teams       []string `json:"teams"`
}

// ListOrgMembers returns org members grouped per user with their role set.
// A non-empty query filters by case-insensitive email substring (access
// console user picker).
func (s *Store) ListOrgMembers(ctx context.Context, q db.Querier, orgID, query string) ([]OrgMemberView, error) {
	sql := `SELECT m.user_id, COALESCE(u.email,''), COALESCE(u.display_name,''), COALESCE(r.name,''), COALESCE(t.name,'')
	             FROM memberships m
	             LEFT JOIN users u ON u.id = m.user_id
	             LEFT JOIN roles r ON r.id = m.role_id
	             LEFT JOIN teams t ON t.id = m.team_id
	             WHERE m.org_id = $1`
	args := []any{orgID}
	if query != "" {
		sql += ` AND u.email ILIKE '%' || $2 || '%' ESCAPE '\'`
		args = append(args, escapeLike(query))
	}
	sql += ` ORDER BY m.user_id`
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byUser := map[string]*OrgMemberView{}
	var order []string
	for rows.Next() {
		var userID, email, displayName, roleName, teamName string
		if err := rows.Scan(&userID, &email, &displayName, &roleName, &teamName); err != nil {
			return nil, err
		}
		mv, ok := byUser[userID]
		if !ok {
			mv = &OrgMemberView{UserID: userID, Email: email, DisplayName: displayName}
			byUser[userID] = mv
			order = append(order, userID)
		}
		if email != "" {
			mv.Email = email
		}
		if displayName != "" {
			mv.DisplayName = displayName
		}
		if roleName != "" && !slices.Contains(mv.Roles, roleName) {
			mv.Roles = append(mv.Roles, roleName)
		}
		if teamName != "" {
			mv.Teams = append(mv.Teams, teamName)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]OrgMemberView, 0, len(order))
	for _, id := range order {
		mv := byUser[id]
		sort.Strings(mv.Roles)
		out = append(out, *mv)
	}
	return out, nil
}

// GetTeamByName resolves a team within an org.
func (s *Store) GetTeamByName(ctx context.Context, q db.Querier, orgID, name string) (*types.Team, error) {
	const sql = `SELECT ` + teamColumns + teamJoin + ` WHERE t.org_id = $1 AND t.name = $2`
	var t types.Team
	err := q.QueryRow(ctx, sql, orgID, name).Scan(&t.ID, &t.OrgID, &t.Name, &t.DisplayName, &t.RoleID, &t.RoleName, &t.KeycloakGroupPath, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTeamNotFound
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// MemberView is a membership row joined with the user profile (console
// view); Role is the granted role's name.
type MemberView struct {
	UserID      string `json:"userId"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	Role        string `json:"role"`
}

// ListMembers returns team members with their user profiles. A non-empty
// query filters by case-insensitive email substring (access console user
// picker).
func (s *Store) ListMembers(ctx context.Context, q db.Querier, orgID, teamID, query string) ([]MemberView, error) {
	sql := `SELECT m.user_id, COALESCE(u.email,''), COALESCE(u.display_name,''), COALESCE(r.name,'')
	             FROM memberships m LEFT JOIN users u ON u.id = m.user_id
	             LEFT JOIN roles r ON r.id = m.role_id
	             WHERE m.org_id = $1 AND m.team_id = $2`
	args := []any{orgID, teamID}
	if query != "" {
		sql += ` AND u.email ILIKE '%' || $3 || '%' ESCAPE '\'`
		args = append(args, escapeLike(query))
	}
	sql += ` ORDER BY m.user_id`
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MemberView
	for rows.Next() {
		var mv MemberView
		if err := rows.Scan(&mv.UserID, &mv.Email, &mv.DisplayName, &mv.Role); err != nil {
			return nil, err
		}
		out = append(out, mv)
	}
	return out, rows.Err()
}

// GroupPath builds the Keycloak group path tenant-<slug>/<team>.
func GroupPath(slug, team string) string {
	return fmt.Sprintf("tenant-%s/%s", slug, team)
}

// likeEscaper escapes ILIKE wildcards so a user-supplied search string is
// matched literally (paired with ESCAPE '\' in the query).
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

func escapeLike(s string) string { return likeEscaper.Replace(s) }

// PlatformResourceEnsurer upserts the tenant's base platform resources
// (platformresources.Service seam, M7.W2).
type PlatformResourceEnsurer interface {
	EnsureBaseResources(ctx context.Context, org *types.Organization) error
}

// Service orchestrates tenant creation across Keycloak and PostgreSQL,
// emitting audit + outbox events in the same DB transaction.
type Service struct {
	db      *db.DB
	idp     IdentityProvider
	clients ClientManager
	// tunnelClients manages the per-cluster kubectl-tunnel Keycloak clients
	// (plan §7.2); nil disables tunnel-client provisioning/kill switches.
	tunnelClients TunnelClientManager
	brokers       IdentityProviderManager
	platform      PlatformResourceEnsurer
	gate          DeletionApprovalGate
	deleter       *Deleter
	store         *Store
	audit         *audit.Store
	orgCache      *OrgCache
}

func NewService(d *db.DB, idp IdentityProvider, store *Store, auditStore *audit.Store) *Service {
	return &Service{db: d, idp: idp, store: store, audit: auditStore}
}

// WithPlatformResources wires the platform-resources module so new tenants
// get their base desired-state rows (keycloak-realm, dns-zone,
// tenant-namespace).
func (s *Service) WithPlatformResources(e PlatformResourceEnsurer) *Service {
	s.platform = e
	return s
}

// WithDeletionApprovalGate wires the approvals module so tenant deletion can
// open a platform-admin lifecycle approval (ADR-0006).
func (s *Service) WithDeletionApprovalGate(g DeletionApprovalGate) *Service {
	s.gate = g
	return s
}

// WithDeleter wires the teardown state machine for the retry endpoint.
func (s *Service) WithDeleter(d *Deleter) *Service {
	s.deleter = d
	return s
}

// WithOrgCache wires the slug→org cache (ADR-0010) consulted by GetTenant,
// the funnel every module's authorizeOrg calls per request. Mutations
// invalidate; all cache failures are fail-open.
func (s *Service) WithOrgCache(c *OrgCache) *Service {
	s.orgCache = c
	return s
}

// invalidateOrgCache evicts the cached org row after a mutation. Safe to
// call with a nil cache (tests and export-openapi wire no cache).
func (s *Service) invalidateOrgCache(ctx context.Context, slug string) {
	if s.orgCache != nil {
		s.orgCache.Invalidate(ctx, slug)
	}
}

// CreateTenant creates the Keycloak org + default groups, the DB projection,
// and the outbox event that seeds OpenFGA base tuples.
func (s *Service) CreateTenant(ctx context.Context, actor, slug, displayName string) (*types.Organization, []types.Team, error) {
	kcOrgID, err := s.idp.CreateOrganization(ctx, slug, displayName)
	if err != nil {
		return nil, nil, fmt.Errorf("tenancy: create keycloak organization: %w", err)
	}
	org := &types.Organization{
		ID:            "org:" + kcOrgID,
		Slug:          slug,
		DisplayName:   displayName,
		KeycloakOrgID: kcOrgID,
	}
	var teams []types.Team
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.CreateOrganization(ctx, tx, org); err != nil {
			return err
		}
		if err := s.store.SeedBuiltinRoles(ctx, tx, org.ID); err != nil {
			return err
		}
		seeds := make([]types.TeamSeed, 0, len(DefaultTeams))
		for _, dt := range DefaultTeams {
			role, err := s.store.GetRoleByName(ctx, tx, org.ID, dt.RoleName)
			if err != nil {
				return err
			}
			team := types.Team{
				OrgID:             org.ID,
				Name:              dt.Name,
				RoleID:            role.ID,
				RoleName:          role.Name,
				KeycloakGroupPath: GroupPath(slug, dt.Name),
			}
			if err := s.store.CreateTeam(ctx, tx, &team); err != nil {
				return err
			}
			teams = append(teams, team)
			seeds = append(seeds, types.TeamSeed{TeamID: team.ID, Name: team.Name, Permissions: role.Permissions})
			if err := s.audit.Record(ctx, tx, &types.AuditEvent{
				OrgID: org.ID, Actor: actor, Action: "team.created", ObjectType: "team", ObjectID: team.ID,
			}); err != nil {
				return err
			}
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: org.ID, Actor: actor, Action: "tenant.created", ObjectType: "organization", ObjectID: org.ID,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, org.ID, types.EventTenantCreated, types.TenantCreatedPayload{
			OrgID: org.ID, Slug: slug, Teams: seeds,
		})
	})
	if err != nil {
		// Best-effort compensation for the external Keycloak write.
		if rbErr := s.idp.DeleteOrganization(ctx, kcOrgID); rbErr != nil {
			return nil, nil, fmt.Errorf("tenancy: %w (rollback keycloak org: %v)", err, rbErr)
		}
		return nil, nil, err
	}
	// Keycloak groups are created after the TX commits; failures are surfaced
	// but leave the org consistent (group creation is idempotent by path).
	for _, tm := range teams {
		if _, err := s.idp.CreateGroup(ctx, tm.KeycloakGroupPath); err != nil {
			return nil, nil, fmt.Errorf("tenancy: create group %s: %w", tm.KeycloakGroupPath, err)
		}
	}
	// Base platform resources after commit (idempotent upserts); failures
	// are surfaced but leave the org consistent, like group creation above.
	if s.platform != nil {
		if err := s.platform.EnsureBaseResources(ctx, org); err != nil {
			return nil, nil, fmt.Errorf("tenancy: ensure base platform resources: %w", err)
		}
	}
	// Kubelogin client after commit (idempotent ensure): kubectl access works
	// out of the box for every tenant (plan §5.4, §7.2).
	if s.clients != nil {
		if err := s.EnsureKubectlClient(ctx, actor, slug); err != nil {
			return nil, nil, fmt.Errorf("tenancy: ensure kubectl client: %w", err)
		}
	}
	// Creator auto-membership: the creating user joins the Keycloak
	// Organization (drives the org token claim), the org-admins group
	// (tenant's first administrator — the only non-circular path to the
	// org-admin role) and the platform-team group; the DB rows + outbox
	// events seed OpenFGA via the tuple writer.
	if actor != "" {
		if err := s.idp.AddOrganizationMember(ctx, kcOrgID, actor); err != nil {
			return nil, nil, fmt.Errorf("tenancy: add creator to org: %w", err)
		}
		findTeam := func(name string) *types.Team {
			for i := range teams {
				if teams[i].Name == name {
					return &teams[i]
				}
			}
			return nil
		}
		joins := []struct {
			team *types.Team
		}{
			{findTeam(OrgAdminsTeamName)},
			{findTeam(PlatformTeamName)},
		}
		for _, j := range joins {
			if j.team == nil {
				return nil, nil, fmt.Errorf("tenancy: default anchor team not found")
			}
			if err := s.idp.AddGroupMember(ctx, j.team.KeycloakGroupPath, actor); err != nil {
				return nil, nil, fmt.Errorf("tenancy: add creator to %s: %w", j.team.Name, err)
			}
		}
		err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
			if err := s.store.UpsertUser(ctx, tx, &types.User{ID: actor}); err != nil {
				return err
			}
			for _, j := range joins {
				if _, err := s.store.AddMembership(ctx, tx, &types.Membership{
					UserID: actor, OrgID: org.ID, TeamID: j.team.ID, RoleID: j.team.RoleID,
				}); err != nil {
					return err
				}
				if err := s.audit.Record(ctx, tx, &types.AuditEvent{
					OrgID: org.ID, Actor: actor, Action: "membership.added", ObjectType: "user", ObjectID: actor,
				}); err != nil {
					return err
				}
				if err := audit.AppendOutbox(ctx, tx, org.ID, types.EventMembershipAdded, types.MembershipPayload{
					OrgID: org.ID, TeamID: j.team.ID, UserID: actor, RoleID: j.team.RoleID,
				}); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	}
	// Defensive: nothing should be cached for a brand-new slug, but a prior
	// delete/recreate race could have left an entry.
	s.invalidateOrgCache(ctx, slug)
	return org, teams, nil
}

// ListTenants returns orgs the caller may see (filtered by Authorizer at the route).
func (s *Service) ListTenants(ctx context.Context) ([]types.Organization, error) {
	return s.store.ListOrganizations(ctx, s.db.Pool)
}

func (s *Service) GetTenant(ctx context.Context, slug string) (*types.Organization, error) {
	if s.orgCache != nil {
		return s.orgCache.Lookup(ctx, slug, func(ctx context.Context) (*types.Organization, error) {
			return s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
		})
	}
	return s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
}

// GetTenantByID resolves an org by its stable ID (org:<id>) — used by
// modules whose records carry the org ID rather than the slug (scaffold
// runs, M8.W3).
func (s *Service) GetTenantByID(ctx context.Context, id string) (*types.Organization, error) {
	return s.store.GetOrganizationByID(ctx, s.db.Pool, id)
}

func (s *Service) ListTeams(ctx context.Context, orgID string) ([]types.Team, error) {
	return s.store.ListTeams(ctx, s.db.Pool, orgID)
}

// ListAllTeams returns every team across all orgs (authz.OrgTeamSync seam).
func (s *Service) ListAllTeams(ctx context.Context) ([]types.Team, error) {
	return s.store.ListAllTeams(ctx, s.db.Pool)
}

// ListActiveTeams returns teams of active orgs only (authz.OrgTeamSync
// seam, ADR-0006).
func (s *Service) ListActiveTeams(ctx context.Context) ([]types.Team, error) {
	return s.store.ListActiveTeams(ctx, s.db.Pool)
}

// UpdateTenantProfile updates the org display name in Keycloak and in the
// DB projection, recording the change in the audit log.
func (s *Service) UpdateTenantProfile(ctx context.Context, actor, slug, displayName string) (*types.Organization, error) {
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return nil, err
	}
	if org.DisplayName == displayName {
		return org, nil
	}
	if err := s.idp.UpdateOrganization(ctx, org.KeycloakOrgID, displayName); err != nil {
		return nil, fmt.Errorf("tenancy: update keycloak organization: %w", err)
	}
	previous := org.DisplayName
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.UpdateOrganizationDisplayName(ctx, tx, org.ID, displayName); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: org.ID, Actor: actor, Action: "organization.updated", ObjectType: "organization", ObjectID: org.ID,
			Payload: []byte(fmt.Sprintf(`{"displayName":{"from":%q,"to":%q}}`, previous, displayName)),
		})
	})
	if err != nil {
		return nil, err
	}
	s.invalidateOrgCache(ctx, slug)
	org.DisplayName = displayName
	return org, nil
}

// CreateTeam creates a team (Keycloak group + DB row) granting the given
// org role (by ID, falling back to role name).
func (s *Service) CreateTeam(ctx context.Context, actor, slug, name, roleID string) (*types.Team, error) {
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return nil, err
	}
	role, err := s.store.GetRoleByID(ctx, s.db.Pool, org.ID, roleID)
	if errors.Is(err, ErrRoleNotFound) {
		role, err = s.store.GetRoleByName(ctx, s.db.Pool, org.ID, roleID)
	}
	if err != nil {
		return nil, err
	}
	team := &types.Team{
		OrgID:             org.ID,
		Name:              name,
		RoleID:            role.ID,
		RoleName:          role.Name,
		KeycloakGroupPath: GroupPath(slug, name),
	}
	// The Keycloak group is created first (idempotent by path); the DB tx
	// then records the projection + audit + outbox atomically.
	if _, err := s.idp.CreateGroup(ctx, team.KeycloakGroupPath); err != nil {
		return nil, fmt.Errorf("tenancy: create group %s: %w", team.KeycloakGroupPath, err)
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.CreateTeam(ctx, tx, team); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: org.ID, Actor: actor, Action: "team.created", ObjectType: "team", ObjectID: team.ID,
			Payload: []byte(fmt.Sprintf(`{"team":%q,"role":%q}`, team.Name, role.Name)),
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, org.ID, types.EventTeamCreated, types.TeamCreatedPayload{
			OrgID: org.ID, TeamID: team.ID, Name: team.Name,
			RoleID: role.ID, RoleName: role.Name, Permissions: role.Permissions,
		})
	})
	if err != nil {
		return nil, err
	}
	return team, nil
}

// EnsureTeam returns the named team, creating it (Keycloak group + DB row
// + audit/outbox) bound to the named org role when missing — the scaffold
// binding-rbac seam (M8.W4, plan §6): component maintainer teams follow
// the same KC group → DB role → outbox → OpenFGA tuple model as every
// other team.
func (s *Service) EnsureTeam(ctx context.Context, actor, slug, name, roleName string) (*types.Team, error) {
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return nil, err
	}
	role, err := s.store.GetRoleByName(ctx, s.db.Pool, org.ID, roleName)
	if err != nil {
		return nil, err
	}
	return s.ensureTeam(ctx, actor, org, name, role)
}

// ensureTeam returns the team with the given name, creating it (with audit
// + outbox) when missing. Used to lazily materialize role anchor teams such
// as org-admins.
func (s *Service) ensureTeam(ctx context.Context, actor string, org *types.Organization, name string, role *types.Role) (*types.Team, error) {
	team, err := s.store.GetTeamByName(ctx, s.db.Pool, org.ID, name)
	if err == nil {
		return team, nil
	}
	if !errors.Is(err, ErrTeamNotFound) {
		return nil, err
	}
	team, err = s.CreateTeam(ctx, actor, org.Slug, name, role.ID)
	if errors.Is(err, ErrTeamNameTaken) {
		// Lost a concurrent create race: the team now exists.
		return s.store.GetTeamByName(ctx, s.db.Pool, org.ID, name)
	}
	return team, err
}

// UpdateTeam changes a non-default team's mutable display name. The team
// name (URL identifier), Keycloak group path, and the OpenFGA tuples keyed
// by the stable team ID are immutable (ADR-0007), so no Keycloak call or
// outbox event is needed — only the DB projection and audit row change.
func (s *Service) UpdateTeam(ctx context.Context, actor, slug, name, displayName string) (*types.Team, error) {
	for _, anchor := range builtinAnchorTeam {
		if anchor == name {
			return nil, ErrDefaultTeam
		}
	}
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return nil, err
	}
	existing, err := s.store.GetTeamByName(ctx, s.db.Pool, org.ID, name)
	if err != nil {
		return nil, err
	}
	if existing.DisplayName == displayName {
		return existing, nil
	}
	var updated *types.Team
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		var err error
		updated, err = s.store.UpdateTeamDisplayName(ctx, tx, org.ID, name, displayName)
		if err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: org.ID, Actor: actor, Action: "team.updated", ObjectType: "team", ObjectID: updated.ID,
			Payload: []byte(fmt.Sprintf(`{"team":%q,"displayName":{"from":%q,"to":%q}}`, name, existing.DisplayName, displayName)),
		})
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

// DeleteTeam removes a non-default team: membership rows, the DB row, and
// the Keycloak group. The outbox team.deleted event retracts the team's
// org permission tuples from OpenFGA. The admin guardrail is re-checked
// inside the TX: deleting the last team whose role carries tenant.admin is
// rejected (tenant lockout).
func (s *Service) DeleteTeam(ctx context.Context, actor, slug, name string) error {
	for _, anchor := range builtinAnchorTeam {
		if anchor == name {
			return ErrDefaultTeam
		}
	}
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return err
	}
	// The members team backs the brokered IdP's Hardcoded Group mapper;
	// deleting it would break brokered logins for the whole tenant.
	if name == membersTeamName {
		brokers, err := s.store.ListIdPBrokers(ctx, s.db.Pool, org.ID)
		if err != nil {
			return err
		}
		if len(brokers) > 0 {
			return ErrMembersTeamInUse
		}
	}
	// Resolve the role the team grants before deletion (needed for the
	// outbox payload that retracts the OpenFGA tuples).
	existing, err := s.store.GetTeamByName(ctx, s.db.Pool, org.ID, name)
	if errors.Is(err, ErrTeamNotFound) {
		return ErrTeamNotFound
	}
	if err != nil {
		return err
	}
	role, err := s.store.GetRoleByID(ctx, s.db.Pool, org.ID, existing.RoleID)
	if err != nil {
		return err
	}
	var deleted *types.Team
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.LockOrgForGuardrail(ctx, tx, org.ID); err != nil {
			return err
		}
		var err error
		deleted, err = s.store.DeleteTeam(ctx, tx, org.ID, name)
		if err != nil {
			return err
		}
		ok, err := s.store.AdminGuardrailHolds(ctx, tx, org.ID)
		if err != nil {
			return err
		}
		if !ok {
			return ErrAdminGuardrail
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: org.ID, Actor: actor, Action: "team.deleted", ObjectType: "team", ObjectID: deleted.ID,
			Payload: []byte(fmt.Sprintf(`{"team":%q,"role":%q}`, deleted.Name, role.Name)),
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, org.ID, types.EventTeamDeleted, types.TeamCreatedPayload{
			OrgID: org.ID, TeamID: deleted.ID, Name: deleted.Name,
			RoleID: role.ID, RoleName: role.Name, Permissions: role.Permissions,
		})
	})
	if err != nil {
		return err
	}
	// Keycloak removal after commit; idempotent (404-tolerant).
	if err := s.idp.DeleteGroup(ctx, deleted.KeycloakGroupPath); err != nil {
		return fmt.Errorf("tenancy: delete group %s: %w", deleted.KeycloakGroupPath, err)
	}
	return nil
}

// HasPermission reports whether the user holds any role containing the
// permission slug in the org (approvals.PermissionResolver seam). DB-backed:
// survives the tenant-freeze FGA tuple sweep.
func (s *Service) HasPermission(ctx context.Context, orgID, userID, permission string) (bool, error) {
	return s.store.HasPermission(ctx, s.db.Pool, orgID, userID, permission)
}

func isUniqueViolation(err error) bool {
	return isSQLState(err, "23505")
}

func isSQLState(err error, state string) bool {
	if err == nil {
		return false
	}
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == state
	}
	return false
}
