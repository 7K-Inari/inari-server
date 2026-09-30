// Role engine (ADR-0013): org-scoped, admin-customizable roles bundling
// slugs from the static permission catalog (authz.PermissionCatalog). Four
// built-ins are seeded per tenant — deletion-protected but editable —
// guarded so at least one team always retains tenant.admin (a tenant can
// never lock itself out).
package tenancy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

var (
	ErrRoleNotFound  = errors.New("role not found")
	ErrRoleNameTaken = errors.New("role name already exists in tenant")
	// ErrBuiltinRole rejects deleting or renaming a built-in role
	// (permission bundles stay editable).
	ErrBuiltinRole = errors.New("built-in roles cannot be deleted or renamed")
	// ErrRoleInUse rejects deleting a role still bound to teams.
	ErrRoleInUse = errors.New("role is still bound to teams")
	// ErrAdminGuardrail rejects any change that would leave no team bound
	// to a role containing tenant.admin (tenant lockout).
	ErrAdminGuardrail = errors.New("at least one team must retain the tenant.admin permission")
)

// roleNamePattern is the DNS-1123 label format role names must follow:
// they become ClusterRole suffixes (tenant-<slug>-<name>) and URL segments.
var roleNamePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

const roleColumns = `id, org_id, name, display_name, description, builtin, permissions, created_at, updated_at`

func scanRole(row interface{ Scan(...any) error }) (*types.Role, error) {
	var r types.Role
	err := row.Scan(&r.ID, &r.OrgID, &r.Name, &r.DisplayName, &r.Description, &r.Builtin, &r.Permissions, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// SeedBuiltinRoles inserts the four built-in roles for an org (idempotent
// per name). Called inside the tenant-creation TX.
func (s *Store) SeedBuiltinRoles(ctx context.Context, q db.Querier, orgID string) error {
	const sql = `INSERT INTO roles (org_id, name, display_name, description, builtin, permissions)
	             VALUES ($1,$2,$3,$4,true,$5) ON CONFLICT (org_id, name) DO NOTHING`
	for _, b := range authz.BuiltinRoles() {
		perms, err := jsonBytes(b.Permissions)
		if err != nil {
			return err
		}
		if _, err := q.Exec(ctx, sql, orgID, b.Name, b.DisplayName, b.Description, perms); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ListRoles(ctx context.Context, q db.Querier, orgID string) ([]types.Role, error) {
	const sql = `SELECT ` + roleColumns + ` FROM roles WHERE org_id = $1 ORDER BY name`
	rows, err := q.Query(ctx, sql, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Role
	for rows.Next() {
		r, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

func (s *Store) GetRoleByName(ctx context.Context, q db.Querier, orgID, name string) (*types.Role, error) {
	const sql = `SELECT ` + roleColumns + ` FROM roles WHERE org_id = $1 AND name = $2`
	r, err := scanRole(q.QueryRow(ctx, sql, orgID, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRoleNotFound
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (s *Store) GetRoleByID(ctx context.Context, q db.Querier, orgID, id string) (*types.Role, error) {
	const sql = `SELECT ` + roleColumns + ` FROM roles WHERE org_id = $1 AND id = $2`
	r, err := scanRole(q.QueryRow(ctx, sql, orgID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRoleNotFound
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (s *Store) CreateRole(ctx context.Context, q db.Querier, r *types.Role) error {
	perms, err := jsonBytes(r.Permissions)
	if err != nil {
		return err
	}
	const sql = `INSERT INTO roles (org_id, name, display_name, description, builtin, permissions)
	             VALUES ($1,$2,$3,$4,false,$5) RETURNING id, created_at, updated_at`
	err = q.QueryRow(ctx, sql, r.OrgID, r.Name, r.DisplayName, r.Description, perms).
		Scan(&r.ID, &r.CreatedAt, &r.UpdatedAt)
	if isUniqueViolation(err) {
		return ErrRoleNameTaken
	}
	return err
}

// UpdateRole rewrites the mutable fields of a role row and returns the
// previous permissions for the outbox payload (read FOR UPDATE in the same
// TX, so a concurrent role edit serializes).
func (s *Store) UpdateRole(ctx context.Context, q db.Querier, r *types.Role) ([]string, error) {
	perms, err := jsonBytes(r.Permissions)
	if err != nil {
		return nil, err
	}
	var old []string
	const getOld = `SELECT permissions FROM roles WHERE org_id = $1 AND id = $2 FOR UPDATE`
	if err := q.QueryRow(ctx, getOld, r.OrgID, r.ID).Scan(&old); err != nil {
		return nil, err
	}
	const upd = `UPDATE roles SET name = $3, display_name = $4, description = $5, permissions = $6, updated_at = now()
	             WHERE org_id = $1 AND id = $2`
	tag, err := q.Exec(ctx, upd, r.OrgID, r.ID, r.Name, r.DisplayName, r.Description, perms)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrRoleNameTaken
		}
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrRoleNotFound
	}
	return old, nil
}

func (s *Store) DeleteRole(ctx context.Context, q db.Querier, orgID, id string) error {
	const sql = `DELETE FROM roles WHERE org_id = $1 AND id = $2`
	tag, err := q.Exec(ctx, sql, orgID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrRoleNotFound
	}
	return nil
}

// ListTeamIDsForRole returns the IDs of teams bound to a role (drives the
// role.updated tuple rewrite).
func (s *Store) ListTeamIDsForRole(ctx context.Context, q db.Querier, roleID string) ([]string, error) {
	const sql = `SELECT id FROM teams WHERE role_id = $1 ORDER BY name`
	rows, err := q.Query(ctx, sql, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// AdminGuardrailHolds reports whether at least one team in the org resolves
// to a role containing tenant.admin. Evaluated inside mutation TXs so a
// violating change rolls back.
func (s *Store) AdminGuardrailHolds(ctx context.Context, q db.Querier, orgID string) (bool, error) {
	const sql = `SELECT EXISTS(
		SELECT 1 FROM teams t JOIN roles r ON r.id = t.role_id
		WHERE t.org_id = $1 AND r.permissions @> '["tenant.admin"]'::jsonb)`
	var ok bool
	return ok, q.QueryRow(ctx, sql, orgID).Scan(&ok)
}

// HasPermission reports whether the user holds any role (via membership)
// containing the permission slug. DB-backed; survives the tenant-freeze FGA
// tuple sweep (approvals fallback, issue #74).
func (s *Store) HasPermission(ctx context.Context, q db.Querier, orgID, userID, permission string) (bool, error) {
	const sql = `SELECT EXISTS(
		SELECT 1 FROM memberships m JOIN roles r ON r.id = m.role_id
		WHERE m.org_id = $1 AND m.user_id = $2 AND r.permissions @> $3::jsonb)`
	needle, err := jsonBytes([]string{permission})
	if err != nil {
		return false, err
	}
	var ok bool
	return ok, q.QueryRow(ctx, sql, orgID, userID, needle).Scan(&ok)
}

// ListMemberRoleNames returns the distinct role names a user holds in an
// org via memberships (the /me/permissions roles projection).
func (s *Store) ListMemberRoleNames(ctx context.Context, q db.Querier, orgID, userID string) ([]string, error) {
	const sql = `SELECT DISTINCT r.name FROM memberships m JOIN roles r ON r.id = m.role_id
	             WHERE m.org_id = $1 AND m.user_id = $2 ORDER BY r.name`
	rows, err := q.Query(ctx, sql, orgID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

// PermissionCatalog exposes the static permission catalog (role editor UI).
func (s *Service) PermissionCatalog() []authz.Permission {
	return authz.PermissionCatalog()
}

func (s *Service) ListRoles(ctx context.Context, orgID string) ([]types.Role, error) {
	return s.store.ListRoles(ctx, s.db.Pool, orgID)
}

// ListMemberRoleNames returns the distinct role names a user holds in an
// org (MeHandler roles projection seam).
func (s *Service) ListMemberRoleNames(ctx context.Context, orgID, userID string) ([]string, error) {
	return s.store.ListMemberRoleNames(ctx, s.db.Pool, orgID, userID)
}

// GetRole resolves a role within a tenant by name or ID.
func (s *Service) GetRole(ctx context.Context, slug, nameOrID string) (*types.Role, error) {
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return nil, err
	}
	r, err := s.store.GetRoleByName(ctx, s.db.Pool, org.ID, nameOrID)
	if errors.Is(err, ErrRoleNotFound) {
		return s.store.GetRoleByID(ctx, s.db.Pool, org.ID, nameOrID)
	}
	return r, err
}

// validateRoleInput checks the name format and the permission set against
// the static catalog.
func validateRoleInput(name string, permissions []string) error {
	if len(name) == 0 || len(name) > 63 || !roleNamePattern.MatchString(name) {
		return fmt.Errorf("tenancy: role name %q must be a DNS-1123 label", name)
	}
	seen := map[string]bool{}
	for _, p := range permissions {
		if !authz.ValidPermission(p) {
			return fmt.Errorf("tenancy: unknown permission %q", p)
		}
		if seen[p] {
			return fmt.Errorf("tenancy: duplicate permission %q", p)
		}
		seen[p] = true
	}
	return nil
}

// CreateRole adds a custom role; audit + outbox role.created land in one TX.
func (s *Service) CreateRole(ctx context.Context, actor, slug string, in *types.Role) (*types.Role, error) {
	if err := validateRoleInput(in.Name, in.Permissions); err != nil {
		return nil, err
	}
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return nil, err
	}
	role := &types.Role{
		OrgID:       org.ID,
		Name:        in.Name,
		DisplayName: in.DisplayName,
		Description: in.Description,
		Permissions: sortedCopy(in.Permissions),
	}
	if role.DisplayName == "" {
		role.DisplayName = role.Name
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.CreateRole(ctx, tx, role); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: org.ID, Actor: actor, Action: "role.created", ObjectType: "role", ObjectID: role.ID,
			Payload: mustJSON(map[string]any{"name": role.Name, "permissions": role.Permissions}),
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, org.ID, types.EventRoleCreated, types.RolePayload{
			OrgID: org.ID, RoleID: role.ID, Name: role.Name, NewPermissions: role.Permissions,
		})
	})
	if err != nil {
		return nil, err
	}
	return role, nil
}

// RolePatch is the editable surface of a role. Name is rejected for
// built-ins (ErrBuiltinRole); permissions replace the whole bundle.
type RolePatch struct {
	Name        *string   `json:"name,omitempty"`
	DisplayName *string   `json:"displayName,omitempty"`
	Description *string   `json:"description,omitempty"`
	Permissions *[]string `json:"permissions,omitempty"`
}

// UpdateRole applies a patch with catalog validation and the admin
// guardrail: the TX updates the row, re-checks that some team still retains
// tenant.admin, and rolls back on violation.
func (s *Service) UpdateRole(ctx context.Context, actor, slug, name string, patch RolePatch) (*types.Role, error) {
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return nil, err
	}
	role, err := s.store.GetRoleByName(ctx, s.db.Pool, org.ID, name)
	if errors.Is(err, ErrRoleNotFound) {
		role, err = s.store.GetRoleByID(ctx, s.db.Pool, org.ID, name)
	}
	if err != nil {
		return nil, err
	}
	if patch.Name != nil && *patch.Name != role.Name && role.Builtin {
		return nil, ErrBuiltinRole
	}
	if patch.Name != nil {
		role.Name = *patch.Name
	}
	if patch.DisplayName != nil {
		role.DisplayName = *patch.DisplayName
	}
	if patch.Description != nil {
		role.Description = *patch.Description
	}
	if patch.Permissions != nil {
		role.Permissions = sortedCopy(*patch.Permissions)
	}
	if err := validateRoleInput(role.Name, role.Permissions); err != nil {
		return nil, err
	}
	var oldPerms []string
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		var err error
		oldPerms, err = s.store.UpdateRole(ctx, tx, role)
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
		teamIDs, err := s.store.ListTeamIDsForRole(ctx, tx, role.ID)
		if err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: org.ID, Actor: actor, Action: "role.updated", ObjectType: "role", ObjectID: role.ID,
			Payload: mustJSON(map[string]any{"name": role.Name, "permissions": role.Permissions}),
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, org.ID, types.EventRoleUpdated, types.RolePayload{
			OrgID: org.ID, RoleID: role.ID, Name: role.Name,
			OldPermissions: oldPerms, NewPermissions: role.Permissions, TeamIDs: teamIDs,
		})
	})
	if err != nil {
		return nil, err
	}
	return role, nil
}

// DeleteRole removes a custom role. Built-ins are never deletable; a role
// bound to teams must be unmapped first.
func (s *Service) DeleteRole(ctx context.Context, actor, slug, name string) error {
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return err
	}
	role, err := s.store.GetRoleByName(ctx, s.db.Pool, org.ID, name)
	if errors.Is(err, ErrRoleNotFound) {
		role, err = s.store.GetRoleByID(ctx, s.db.Pool, org.ID, name)
	}
	if err != nil {
		return err
	}
	if role.Builtin {
		return ErrBuiltinRole
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		teamIDs, err := s.store.ListTeamIDsForRole(ctx, tx, role.ID)
		if err != nil {
			return err
		}
		if len(teamIDs) > 0 {
			return ErrRoleInUse
		}
		if err := s.store.DeleteRole(ctx, tx, org.ID, role.ID); err != nil {
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
			OrgID: org.ID, Actor: actor, Action: "role.deleted", ObjectType: "role", ObjectID: role.ID,
			Payload: mustJSON(map[string]any{"name": role.Name}),
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, org.ID, types.EventRoleDeleted, types.RolePayload{
			OrgID: org.ID, RoleID: role.ID, Name: role.Name, OldPermissions: role.Permissions,
		})
	})
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// jsonBytes marshals a value for a jsonb column/parameter.
func jsonBytes(v any) ([]byte, error) { return json.Marshal(v) }
