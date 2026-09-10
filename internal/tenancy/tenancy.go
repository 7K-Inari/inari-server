// Package tenancy implements the Tenancy & Identity module: tenant lifecycle
// backed by Keycloak Organizations, teams as groups tenant-<slug>/<team>,
// and DB projection with audit + outbox writes.
package tenancy

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/audit"
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
}

// DefaultTeams are created with every tenant; each grants its org role.
var DefaultTeams = []struct {
	Name string
	Role types.Role
}{
	{"platform-team", types.RolePlatformEngineer},
	{"developers", types.RoleDeveloper},
	{"viewers", types.RoleViewer},
}

var (
	ErrSlugTaken     = errors.New("tenant slug already exists")
	ErrOrgNotFound   = errors.New("organization not found")
	ErrUserNotFound  = errors.New("user not found")
	ErrTeamNotFound  = errors.New("team not found")
	ErrTeamNameTaken = errors.New("team name already exists in tenant")
	ErrDefaultTeam   = errors.New("default teams cannot be deleted")
)

// PlatformTeamName is the default team that receives the tenant creator.
const PlatformTeamName = "platform-team"

// Store is the PostgreSQL projection of tenancy state.
type Store struct{}

func NewStore() *Store { return &Store{} }

func (s *Store) CreateOrganization(ctx context.Context, q db.Querier, org *types.Organization) error {
	const sql = `INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ($1,$2,$3,$4) RETURNING created_at`
	err := q.QueryRow(ctx, sql, org.ID, org.Slug, org.DisplayName, org.KeycloakOrgID).Scan(&org.CreatedAt)
	if isUniqueViolation(err) {
		return ErrSlugTaken
	}
	return err
}

func (s *Store) GetOrganizationBySlug(ctx context.Context, q db.Querier, slug string) (*types.Organization, error) {
	const sql = `SELECT id, slug, display_name, keycloak_org_id, created_at FROM organizations WHERE slug = $1`
	var org types.Organization
	err := q.QueryRow(ctx, sql, slug).Scan(&org.ID, &org.Slug, &org.DisplayName, &org.KeycloakOrgID, &org.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrOrgNotFound
	}
	if err != nil {
		return nil, err
	}
	return &org, nil
}

func (s *Store) ListOrganizations(ctx context.Context, q db.Querier) ([]types.Organization, error) {
	const sql = `SELECT id, slug, display_name, keycloak_org_id, created_at FROM organizations ORDER BY created_at`
	rows, err := q.Query(ctx, sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Organization
	for rows.Next() {
		var o types.Organization
		if err := rows.Scan(&o.ID, &o.Slug, &o.DisplayName, &o.KeycloakOrgID, &o.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) CreateTeam(ctx context.Context, q db.Querier, team *types.Team) error {
	const sql = `INSERT INTO teams (org_id, name, role, keycloak_group_path) VALUES ($1,$2,$3,$4) RETURNING id, created_at`
	err := q.QueryRow(ctx, sql, team.OrgID, team.Name, team.Role, team.KeycloakGroupPath).Scan(&team.ID, &team.CreatedAt)
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

// DeleteTeam removes a team row and returns the deleted record for audit
// payloads; membership rows cascade away via FK.
func (s *Store) DeleteTeam(ctx context.Context, q db.Querier, orgID, name string) (*types.Team, error) {
	const sql = `DELETE FROM teams WHERE org_id = $1 AND name = $2
	             RETURNING id, org_id, name, role, keycloak_group_path, created_at`
	var t types.Team
	err := q.QueryRow(ctx, sql, orgID, name).Scan(&t.ID, &t.OrgID, &t.Name, &t.Role, &t.KeycloakGroupPath, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTeamNotFound
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) ListTeams(ctx context.Context, q db.Querier, orgID string) ([]types.Team, error) {
	const sql = `SELECT id, org_id, name, role, keycloak_group_path, created_at FROM teams WHERE org_id = $1 ORDER BY name`
	rows, err := q.Query(ctx, sql, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Team
	for rows.Next() {
		var t types.Team
		if err := rows.Scan(&t.ID, &t.OrgID, &t.Name, &t.Role, &t.KeycloakGroupPath, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) UpsertUser(ctx context.Context, q db.Querier, u *types.User) error {
	const sql = `INSERT INTO users (id, email, display_name) VALUES ($1,$2,$3)
	             ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email, display_name = EXCLUDED.display_name`
	_, err := q.Exec(ctx, sql, u.ID, u.Email, u.DisplayName)
	return err
}

// AddMembership inserts a membership row, reporting whether a row was
// actually inserted (false on conflict). Callers use the flag to emit
// outbox events exactly once even under concurrent adds.
func (s *Store) AddMembership(ctx context.Context, q db.Querier, m *types.Membership) (bool, error) {
	const sql = `INSERT INTO memberships (user_id, org_id, team_id, role) VALUES ($1,$2,$3,$4)
	             ON CONFLICT (user_id, org_id, role) DO NOTHING`
	var teamID *string
	if m.TeamID != "" {
		teamID = &m.TeamID
	}
	tag, err := q.Exec(ctx, sql, m.UserID, m.OrgID, teamID, m.Role)
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
	Role      types.Role
}

// ListMembershipsWithPaths returns all of a user's memberships in an org
// with the group's Keycloak path.
func (s *Store) ListMembershipsWithPaths(ctx context.Context, q db.Querier, orgID, userID string) ([]MembershipWithPath, error) {
	const sql = `SELECT m.team_id, COALESCE(t.keycloak_group_path,''), m.role
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
		if err := rows.Scan(&teamID, &mp.GroupPath, &mp.Role); err != nil {
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
	const sql = `DELETE FROM memberships WHERE org_id = $1 AND user_id = $2 RETURNING team_id, role`
	rows, err := q.Query(ctx, sql, orgID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Membership
	for rows.Next() {
		var m types.Membership
		var teamID *string
		if err := rows.Scan(&teamID, &m.Role); err != nil {
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

// OrgMemberView is the org-wide console view of a user: profile, highest
// role, and the teams they belong to.
type OrgMemberView struct {
	UserID      string   `json:"userId"`
	Email       string   `json:"email"`
	DisplayName string   `json:"displayName"`
	Role        string   `json:"role"`
	Teams       []string `json:"teams"`
}

// ListOrgMembers returns org members grouped per user with highest role.
func (s *Store) ListOrgMembers(ctx context.Context, q db.Querier, orgID string) ([]OrgMemberView, error) {
	const sql = `SELECT m.user_id, COALESCE(u.email,''), COALESCE(u.display_name,''), m.role, COALESCE(t.name,'')
	             FROM memberships m
	             LEFT JOIN users u ON u.id = m.user_id
	             LEFT JOIN teams t ON t.id = m.team_id
	             WHERE m.org_id = $1 ORDER BY m.user_id`
	rows, err := q.Query(ctx, sql, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rank := map[types.Role]int{
		types.RoleViewer: 1, types.RoleDeveloper: 2, types.RolePlatformEngineer: 3, types.RoleOrgAdmin: 4,
	}
	byUser := map[string]*OrgMemberView{}
	var order []string
	for rows.Next() {
		var userID, email, displayName, teamName string
		var role types.Role
		if err := rows.Scan(&userID, &email, &displayName, &role, &teamName); err != nil {
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
		if rank[role] > rank[types.Role(mv.Role)] {
			mv.Role = string(role)
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
		out = append(out, *byUser[id])
	}
	return out, nil
}

// GetTeamByName resolves a team within an org.
func (s *Store) GetTeamByName(ctx context.Context, q db.Querier, orgID, name string) (*types.Team, error) {
	const sql = `SELECT id, org_id, name, role, keycloak_group_path, created_at FROM teams WHERE org_id = $1 AND name = $2`
	var t types.Team
	err := q.QueryRow(ctx, sql, orgID, name).Scan(&t.ID, &t.OrgID, &t.Name, &t.Role, &t.KeycloakGroupPath, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTeamNotFound
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// MemberView is a membership row joined with the user profile (console view).
type MemberView struct {
	UserID      string `json:"userId"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	Role        string `json:"role"`
}

// ListMembers returns team members with their user profiles.
func (s *Store) ListMembers(ctx context.Context, q db.Querier, orgID, teamID string) ([]MemberView, error) {
	const sql = `SELECT m.user_id, COALESCE(u.email,''), COALESCE(u.display_name,''), m.role
	             FROM memberships m LEFT JOIN users u ON u.id = m.user_id
	             WHERE m.org_id = $1 AND m.team_id = $2 ORDER BY m.user_id`
	rows, err := q.Query(ctx, sql, orgID, teamID)
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

// HighestRole returns the highest role a user holds in an org
// (org-admin > platform-engineer > developer > viewer). Returns false when
// the user is not a member.
func (s *Store) HighestRole(ctx context.Context, q db.Querier, orgID, userID string) (types.Role, bool, error) {
	const sql = `SELECT role FROM memberships WHERE org_id = $1 AND user_id = $2`
	rows, err := q.Query(ctx, sql, orgID, userID)
	if err != nil {
		return "", false, err
	}
	defer rows.Close()
	best := types.Role("")
	rank := map[types.Role]int{
		types.RoleViewer: 1, types.RoleDeveloper: 2, types.RolePlatformEngineer: 3, types.RoleOrgAdmin: 4,
	}
	for rows.Next() {
		var r types.Role
		if err := rows.Scan(&r); err != nil {
			return "", false, err
		}
		if rank[r] > rank[best] {
			best = r
		}
	}
	return best, best != "", rows.Err()
}

// Service orchestrates tenant creation across Keycloak and PostgreSQL,
// emitting audit + outbox events in the same DB transaction.
type Service struct {
	db      *db.DB
	idp     IdentityProvider
	clients ClientManager
	brokers IdentityProviderManager
	store   *Store
	audit   *audit.Store
}

func NewService(d *db.DB, idp IdentityProvider, store *Store, auditStore *audit.Store) *Service {
	return &Service{db: d, idp: idp, store: store, audit: auditStore}
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
		seeds := make([]types.TeamSeed, 0, len(DefaultTeams))
		for _, dt := range DefaultTeams {
			team := types.Team{
				OrgID:             org.ID,
				Name:              dt.Name,
				Role:              dt.Role,
				KeycloakGroupPath: GroupPath(slug, dt.Name),
			}
			if err := s.store.CreateTeam(ctx, tx, &team); err != nil {
				return err
			}
			teams = append(teams, team)
			seeds = append(seeds, types.TeamSeed{TeamID: team.ID, Name: team.Name, Role: dt.Role})
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
	// Creator auto-membership: the creating user joins the Keycloak
	// Organization (drives the org token claim) and the platform-team group;
	// the DB row + outbox event seed OpenFGA via the tuple writer.
	if actor != "" {
		if err := s.idp.AddOrganizationMember(ctx, kcOrgID, actor); err != nil {
			return nil, nil, fmt.Errorf("tenancy: add creator to org: %w", err)
		}
		if err := s.idp.AddGroupMember(ctx, GroupPath(slug, PlatformTeamName), actor); err != nil {
			return nil, nil, fmt.Errorf("tenancy: add creator to %s: %w", PlatformTeamName, err)
		}
		var platformTeam *types.Team
		for i := range teams {
			if teams[i].Name == PlatformTeamName {
				platformTeam = &teams[i]
			}
		}
		if platformTeam == nil {
			return nil, nil, fmt.Errorf("tenancy: %s not among default teams", PlatformTeamName)
		}
		err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
			if err := s.store.UpsertUser(ctx, tx, &types.User{ID: actor}); err != nil {
				return err
			}
			if _, err := s.store.AddMembership(ctx, tx, &types.Membership{
				UserID: actor, OrgID: org.ID, TeamID: platformTeam.ID, Role: types.RolePlatformEngineer,
			}); err != nil {
				return err
			}
			if err := s.audit.Record(ctx, tx, &types.AuditEvent{
				OrgID: org.ID, Actor: actor, Action: "membership.added", ObjectType: "user", ObjectID: actor,
			}); err != nil {
				return err
			}
			return audit.AppendOutbox(ctx, tx, org.ID, types.EventMembershipAdded, types.MembershipPayload{
				OrgID: org.ID, TeamID: platformTeam.ID, UserID: actor, Role: types.RolePlatformEngineer,
			})
		})
		if err != nil {
			return nil, nil, err
		}
	}
	return org, teams, nil
}

// ListTenants returns orgs the caller may see (filtered by Authorizer at the route).
func (s *Service) ListTenants(ctx context.Context) ([]types.Organization, error) {
	return s.store.ListOrganizations(ctx, s.db.Pool)
}

func (s *Service) GetTenant(ctx context.Context, slug string) (*types.Organization, error) {
	return s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
}

func (s *Service) ListTeams(ctx context.Context, orgID string) ([]types.Team, error) {
	return s.store.ListTeams(ctx, s.db.Pool, orgID)
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
	org.DisplayName = displayName
	return org, nil
}

// roleAnchorTeam maps an org role to the team whose membership grants it.
// org-admins is not among DefaultTeams (created lazily on first assignment).
var roleAnchorTeam = map[types.Role]string{
	types.RoleOrgAdmin:         "org-admins",
	types.RolePlatformEngineer: "platform-team",
	types.RoleDeveloper:        "developers",
	types.RoleViewer:           "viewers",
}

// AnchorTeamForRole returns the team granting the role, and whether the role
// is valid.
func AnchorTeamForRole(r types.Role) (string, bool) {
	name, ok := roleAnchorTeam[r]
	return name, ok
}

// CreateTeam creates a team (Keycloak group + DB row) granting the given
// org role; role defaults to viewer.
func (s *Service) CreateTeam(ctx context.Context, actor, slug, name string, role types.Role) (*types.Team, error) {
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return nil, err
	}
	team := &types.Team{
		OrgID:             org.ID,
		Name:              name,
		Role:              role,
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
			Payload: []byte(fmt.Sprintf(`{"team":%q,"role":%q}`, team.Name, role)),
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, org.ID, types.EventTeamCreated, types.TeamCreatedPayload{
			OrgID: org.ID, TeamID: team.ID, Name: team.Name, Role: role,
		})
	})
	if err != nil {
		return nil, err
	}
	return team, nil
}

// ensureTeam returns the team with the given name, creating it (with audit
// + outbox) when missing. Used to lazily materialize role anchor teams such
// as org-admins.
func (s *Service) ensureTeam(ctx context.Context, actor string, org *types.Organization, name string, role types.Role) (*types.Team, error) {
	team, err := s.store.GetTeamByName(ctx, s.db.Pool, org.ID, name)
	if err == nil {
		return team, nil
	}
	if !errors.Is(err, ErrTeamNotFound) {
		return nil, err
	}
	return s.CreateTeam(ctx, actor, org.Slug, name, role)
}

// DeleteTeam removes a non-default team: membership rows, the DB row, and
// the Keycloak group. The outbox team.deleted event retracts the team's
// org role tuple from OpenFGA.
func (s *Service) DeleteTeam(ctx context.Context, actor, slug, name string) error {
	for _, anchor := range roleAnchorTeam {
		if anchor == name {
			return ErrDefaultTeam
		}
	}
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return err
	}
	// Resolve the role the team grants before deletion (needed for the
	// outbox payload that retracts the OpenFGA tuple).
	existing, err := s.store.GetTeamByName(ctx, s.db.Pool, org.ID, name)
	if errors.Is(err, ErrTeamNotFound) {
		return ErrTeamNotFound
	}
	if err != nil {
		return err
	}
	role := existing.Role
	var deleted *types.Team
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		var err error
		deleted, err = s.store.DeleteTeam(ctx, tx, org.ID, name)
		if err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: org.ID, Actor: actor, Action: "team.deleted", ObjectType: "team", ObjectID: deleted.ID,
			Payload: []byte(fmt.Sprintf(`{"team":%q,"role":%q}`, deleted.Name, role)),
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, org.ID, types.EventTeamDeleted, types.TeamCreatedPayload{
			OrgID: org.ID, TeamID: deleted.ID, Name: deleted.Name, Role: role,
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

// RoleOf resolves a user's highest org role (approvals.RoleResolver seam).
// Non-members get the empty role with no error.
func (s *Service) RoleOf(ctx context.Context, orgID, userID string) (types.Role, error) {
	role, _, err := s.store.HighestRole(ctx, s.db.Pool, orgID, userID)
	return role, err
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}
