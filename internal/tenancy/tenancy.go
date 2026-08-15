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
	DeleteOrganization(ctx context.Context, kcOrgID string) error
	CreateGroup(ctx context.Context, path string) (groupID string, err error)
	// ListOrganizations returns the aliases of orgs the user is a member of.
	ListOrganizations(ctx context.Context, userID string) ([]string, error)
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
	ErrSlugTaken   = errors.New("tenant slug already exists")
	ErrOrgNotFound = errors.New("organization not found")
)

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
	const sql = `INSERT INTO teams (org_id, name, keycloak_group_path) VALUES ($1,$2,$3) RETURNING id, created_at`
	return q.QueryRow(ctx, sql, team.OrgID, team.Name, team.KeycloakGroupPath).Scan(&team.ID, &team.CreatedAt)
}

func (s *Store) ListTeams(ctx context.Context, q db.Querier, orgID string) ([]types.Team, error) {
	const sql = `SELECT id, org_id, name, keycloak_group_path, created_at FROM teams WHERE org_id = $1 ORDER BY name`
	rows, err := q.Query(ctx, sql, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Team
	for rows.Next() {
		var t types.Team
		if err := rows.Scan(&t.ID, &t.OrgID, &t.Name, &t.KeycloakGroupPath, &t.CreatedAt); err != nil {
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

func (s *Store) AddMembership(ctx context.Context, q db.Querier, m *types.Membership) error {
	const sql = `INSERT INTO memberships (user_id, org_id, team_id, role) VALUES ($1,$2,$3,$4)
	             ON CONFLICT (user_id, org_id, role) DO NOTHING`
	var teamID *string
	if m.TeamID != "" {
		teamID = &m.TeamID
	}
	_, err := q.Exec(ctx, sql, m.UserID, m.OrgID, teamID, m.Role)
	return err
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
	db    *db.DB
	idp   IdentityProvider
	store *Store
	audit *audit.Store
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
