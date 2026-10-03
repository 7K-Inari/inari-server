// Identity client management and declarative RBAC mappings (Settings design
// §3.1). Client secrets live only in Keycloak — returned once at
// create/rotate, never persisted; the DB projection carries metadata only.
package tenancy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

var (
	ErrClientNotFound  = errors.New("identity client not found")
	ErrClientNameTaken = errors.New("client name already exists in tenant")
)

// ClientManager abstracts the Keycloak Admin client CRUD the identity
// section needs (implemented by KeycloakAdmin; faked in tests).
type ClientManager interface {
	CreateClient(ctx context.Context, spec ClientSpec) (secret string, err error)
	GetClient(ctx context.Context, clientID string) (*ClientSpec, error)
	UpdateClient(ctx context.Context, spec ClientSpec) error
	DisableClient(ctx context.Context, clientID string) error
	RotateClientSecret(ctx context.Context, clientID string) (secret string, err error)
}

// WithClientManager wires the Keycloak client CRUD backend used by the
// identity routes.
func (s *Service) WithClientManager(cm ClientManager) *Service {
	s.clients = cm
	return s
}

// identityClientID renders the org-scoped clientId org-<org>-<name>.
func identityClientID(slug, name string) string {
	return "org-" + slug + "-" + name
}

// CreateIdentityClient provisions the Keycloak client, records the metadata
// projection + audit in one TX, and returns the secret exactly once
// (confidential clients only).
func (s *Service) CreateIdentityClient(ctx context.Context, actor, slug string, in *types.IdentityClient) (*types.IdentityClient, string, error) {
	if s.clients == nil {
		return nil, "", errors.New("tenancy: identity client manager not configured")
	}
	if in.Type != types.IdentityClientTypeService && in.Type != types.IdentityClientTypePublic {
		return nil, "", fmt.Errorf("tenancy: invalid client type %q", in.Type)
	}
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return nil, "", err
	}
	client := &types.IdentityClient{
		ClientID:     identityClientID(slug, in.Name),
		OrgID:        org.ID,
		Name:         in.Name,
		Type:         in.Type,
		Audiences:    in.Audiences,
		Scopes:       in.Scopes,
		RedirectURIs: in.RedirectURIs,
		Status:       types.IdentityClientStatusActive,
	}
	// Fast-path name conflict against the projection so a duplicate fails
	// before any Keycloak write.
	if _, err := s.store.GetIdentityClient(ctx, s.db.Pool, org.ID, client.ClientID); err == nil {
		return nil, "", ErrClientNameTaken
	} else if !errors.Is(err, ErrClientNotFound) {
		return nil, "", err
	}
	secret, err := s.clients.CreateClient(ctx, ClientSpec{
		ClientID:     client.ClientID,
		Name:         client.Name,
		ClientType:   client.Type,
		Audiences:    client.Audiences,
		Scopes:       client.Scopes,
		RedirectURIs: client.RedirectURIs,
	})
	if err != nil {
		return nil, "", fmt.Errorf("tenancy: create keycloak client: %w", err)
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.CreateIdentityClient(ctx, tx, client); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: org.ID, Actor: actor, Action: "identity.client.created", ObjectType: "identity_client", ObjectID: client.ClientID,
			Payload: []byte(fmt.Sprintf(`{"name":%q,"type":%q}`, client.Name, client.Type)),
		})
	})
	if err != nil {
		// Best-effort compensation for the external Keycloak write.
		if rbErr := s.clients.DisableClient(ctx, client.ClientID); rbErr != nil {
			return nil, "", fmt.Errorf("tenancy: %w (rollback keycloak client: %v)", err, rbErr)
		}
		return nil, "", err
	}
	return client, secret, nil
}

func (s *Service) ListIdentityClients(ctx context.Context, orgID string) ([]types.IdentityClient, error) {
	return s.store.ListIdentityClients(ctx, s.db.Pool, orgID)
}

// GetIdentityClient resolves a client within a tenant by its full clientId.
func (s *Service) GetIdentityClient(ctx context.Context, slug, clientID string) (*types.IdentityClient, error) {
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return nil, err
	}
	return s.store.GetIdentityClient(ctx, s.db.Pool, org.ID, clientID)
}

// UpdateIdentityClient applies a full spec update (name, audiences, scopes,
// redirect URIs) to Keycloak and the DB projection.
func (s *Service) UpdateIdentityClient(ctx context.Context, actor, slug string, client *types.IdentityClient) error {
	if s.clients == nil {
		return errors.New("tenancy: identity client manager not configured")
	}
	if err := s.clients.UpdateClient(ctx, ClientSpec{
		ClientID:     client.ClientID,
		Name:         client.Name,
		ClientType:   client.Type,
		Audiences:    client.Audiences,
		Scopes:       client.Scopes,
		RedirectURIs: client.RedirectURIs,
		Enabled:      client.Status == types.IdentityClientStatusActive,
	}); err != nil {
		return fmt.Errorf("tenancy: update keycloak client: %w", err)
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.UpdateIdentityClient(ctx, tx, client); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: client.OrgID, Actor: actor, Action: "identity.client.updated", ObjectType: "identity_client", ObjectID: client.ClientID,
		})
	})
}

// DisableIdentityClient disables the Keycloak client (in-flight tokens
// expire on their short TTL) and marks the projection disabled; the row is
// retained for audit.
func (s *Service) DisableIdentityClient(ctx context.Context, actor, slug, clientID string) error {
	if s.clients == nil {
		return errors.New("tenancy: identity client manager not configured")
	}
	client, err := s.GetIdentityClient(ctx, slug, clientID)
	if err != nil {
		return err
	}
	if err := s.clients.DisableClient(ctx, clientID); err != nil {
		return fmt.Errorf("tenancy: disable keycloak client: %w", err)
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.SetIdentityClientStatus(ctx, tx, client.OrgID, clientID, types.IdentityClientStatusDisabled); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: client.OrgID, Actor: actor, Action: "identity.client.disabled", ObjectType: "identity_client", ObjectID: clientID,
		})
	})
}

// RotateIdentityClientSecret regenerates the Keycloak secret and returns it
// exactly once; nothing is persisted server-side beyond the audit row.
func (s *Service) RotateIdentityClientSecret(ctx context.Context, actor, slug, clientID string) (string, error) {
	if s.clients == nil {
		return "", errors.New("tenancy: identity client manager not configured")
	}
	client, err := s.GetIdentityClient(ctx, slug, clientID)
	if err != nil {
		return "", err
	}
	if client.Type != types.IdentityClientTypeService {
		return "", fmt.Errorf("tenancy: public clients have no secret to rotate")
	}
	secret, err := s.clients.RotateClientSecret(ctx, clientID)
	if err != nil {
		return "", fmt.Errorf("tenancy: rotate keycloak client secret: %w", err)
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: client.OrgID, Actor: actor, Action: "identity.client.secret_rotated", ObjectType: "identity_client", ObjectID: clientID,
		})
	})
	if err != nil {
		return "", err
	}
	return secret, nil
}

// EnsureKubectlClient idempotently provisions the per-tenant kubelogin
// client (KubectlClientSpec) in Keycloak and its metadata projection, so
// `inari cluster kubeconfig` works out of the box (plan §5.4, §7.2). Called
// from CreateTenant and safe to re-run for tenants created before this
// feature; the audit event is recorded only when the client is created.
func (s *Service) EnsureKubectlClient(ctx context.Context, actor, slug string) error {
	if s.clients == nil {
		return errors.New("tenancy: identity client manager not configured")
	}
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return err
	}
	clientID := KubectlClientID(slug)
	if _, err := s.store.GetIdentityClient(ctx, s.db.Pool, org.ID, clientID); err == nil {
		return nil // already provisioned
	} else if !errors.Is(err, ErrClientNotFound) {
		return err
	}
	spec := KubectlClientSpec(slug)
	if _, err := s.clients.CreateClient(ctx, spec); err != nil {
		return fmt.Errorf("tenancy: create kubectl keycloak client: %w", err)
	}
	client := &types.IdentityClient{
		ClientID:     clientID,
		OrgID:        org.ID,
		Name:         spec.Name,
		Type:         types.IdentityClientTypePublic,
		Audiences:    spec.Audiences,
		Scopes:       spec.Scopes,
		RedirectURIs: spec.RedirectURIs,
		Status:       types.IdentityClientStatusActive,
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.CreateIdentityClient(ctx, tx, client); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: org.ID, Actor: actor, Action: "identity.client.kubectl_ensured", ObjectType: "identity_client", ObjectID: clientID,
		})
	})
	if err != nil {
		// Best-effort compensation for the external Keycloak write.
		if rbErr := s.clients.DisableClient(ctx, clientID); rbErr != nil {
			return fmt.Errorf("tenancy: %w (rollback keycloak client: %v)", err, rbErr)
		}
		return err
	}
	return nil
}

// TunnelClientManager abstracts the per-cluster kubectl-tunnel client
// lifecycle (implemented by KeycloakAdmin; faked in tests). Kept separate
// from ClientManager: the tunnel client is per-cluster, not per-tenant, and
// is provisioned from the cluster-registration flow (plan §7.2).
type TunnelClientManager interface {
	CreateTunnelClient(ctx context.Context, clusterID string) (string, error)
	DisableTunnelClient(ctx context.Context, clusterID string) error
	RevokeTunnelClient(ctx context.Context, clusterID string) error
}

// WithTunnelClientManager wires the tunnel-client lifecycle backend.
func (s *Service) WithTunnelClientManager(m TunnelClientManager) *Service {
	s.tunnelClients = m
	return s
}

// EnsureTunnelClient idempotently provisions the per-cluster tunnel client
// tunnel-<cluster-id> (client-credentials only, hardcoded cluster_id claim,
// audience inari-kubeproxy). The audit event is recorded on every call —
// registration is the only caller and it runs once per cluster.
func (s *Service) EnsureTunnelClient(ctx context.Context, actor, orgID, clusterID string) (string, error) {
	if s.tunnelClients == nil {
		return "", errors.New("tenancy: tunnel client manager not configured")
	}
	clientID, err := s.tunnelClients.CreateTunnelClient(ctx, clusterID)
	if err != nil {
		return "", fmt.Errorf("tenancy: create tunnel keycloak client: %w", err)
	}
	if err := s.audit.Record(ctx, s.db.Pool, &types.AuditEvent{
		OrgID: orgID, Actor: actor, Action: "identity.client.tunnel_ensured", ObjectType: "identity_client", ObjectID: clientID,
	}); err != nil {
		return "", err
	}
	return clientID, nil
}

// DisableTunnelClient disables the cluster's tunnel client (kubectl-tunnel
// kill switch; in-flight tokens expire on their short TTL).
func (s *Service) DisableTunnelClient(ctx context.Context, actor, orgID, clusterID string) error {
	if s.tunnelClients == nil {
		return errors.New("tenancy: tunnel client manager not configured")
	}
	if err := s.tunnelClients.DisableTunnelClient(ctx, clusterID); err != nil {
		return fmt.Errorf("tenancy: disable tunnel keycloak client: %w", err)
	}
	return s.audit.Record(ctx, s.db.Pool, &types.AuditEvent{
		OrgID: orgID, Actor: actor, Action: "identity.client.tunnel_disabled", ObjectType: "identity_client", ObjectID: TunnelClientID(clusterID),
	})
}

// RevokeTunnelClient deletes the cluster's tunnel client outright (terminal
// kill switch, e.g. on cluster revocation).
func (s *Service) RevokeTunnelClient(ctx context.Context, actor, orgID, clusterID string) error {
	if s.tunnelClients == nil {
		return errors.New("tenancy: tunnel client manager not configured")
	}
	if err := s.tunnelClients.RevokeTunnelClient(ctx, clusterID); err != nil {
		return fmt.Errorf("tenancy: revoke tunnel keycloak client: %w", err)
	}
	return s.audit.Record(ctx, s.db.Pool, &types.AuditEvent{
		OrgID: orgID, Actor: actor, Action: "identity.client.tunnel_revoked", ObjectType: "identity_client", ObjectID: TunnelClientID(clusterID),
	})
}

// GroupMemberCount returns the number of Keycloak users in a group path,
// best-effort for the RBAC matrix view.
func (s *Service) GroupMemberCount(ctx context.Context, groupPath string) (int, error) {
	ids, err := s.idp.ListGroupMembers(ctx, groupPath)
	if err != nil {
		return 0, err
	}
	return len(ids), nil
}

// SetRBACMappings applies the declarative team → role mapping set
// atomically: every mapping is validated first, then all role changes land
// in one TX with a single audit row and one outbox event driving the
// OpenFGA tuple rewrite. The admin guardrail is re-checked inside the TX:
// a mapping set that leaves no team with tenant.admin rolls back (409).
func (s *Service) SetRBACMappings(ctx context.Context, actor, slug string, mappings []types.TeamRoleMapping) ([]types.TeamRoleChange, error) {
	// Reject duplicate teams up front: each entry is compared against the
	// team's original role, so a repeated team would emit multiple changes
	// with the same old role and the tuple writer would grant every new
	// role instead of the last one.
	seen := make(map[string]bool, len(mappings))
	for _, m := range mappings {
		if seen[m.Team] {
			return nil, fmt.Errorf("tenancy: duplicate team %q in mappings", m.Team)
		}
		seen[m.Team] = true
	}
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return nil, err
	}
	// Validate everything before touching the DB so a bad entry fails the
	// whole request with no partial writes.
	teams := make(map[string]*types.Team, len(mappings))
	roles := make(map[string]*types.Role, len(mappings))
	for _, m := range mappings {
		team, err := s.store.GetTeamByName(ctx, s.db.Pool, org.ID, m.Team)
		if err != nil {
			return nil, err
		}
		teams[m.Team] = team
		role, err := s.store.GetRoleByID(ctx, s.db.Pool, org.ID, m.RoleID)
		if errors.Is(err, ErrRoleNotFound) {
			role, err = s.store.GetRoleByName(ctx, s.db.Pool, org.ID, m.RoleID)
		}
		if err != nil {
			return nil, err
		}
		roles[m.Team] = role
	}
	var changes []types.TeamRoleChange
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.LockOrgForGuardrail(ctx, tx, org.ID); err != nil {
			return err
		}
		for _, m := range mappings {
			team := teams[m.Team]
			newRole := roles[m.Team]
			if team.RoleID == newRole.ID {
				continue
			}
			oldPerms, err := s.rolePermissions(ctx, tx, org.ID, team.RoleID)
			if err != nil {
				return err
			}
			if err := s.store.UpdateTeamRole(ctx, tx, team.ID, newRole.ID); err != nil {
				return err
			}
			changes = append(changes, types.TeamRoleChange{
				TeamID: team.ID, Name: team.Name,
				OldRoleID: team.RoleID, OldPermissions: oldPerms,
				NewRoleID: newRole.ID, NewPermissions: newRole.Permissions,
			})
		}
		if len(changes) == 0 {
			return nil
		}
		ok, err := s.store.AdminGuardrailHolds(ctx, tx, org.ID)
		if err != nil {
			return err
		}
		if !ok {
			return ErrAdminGuardrail
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: org.ID, Actor: actor, Action: "rbac.mappings.updated", ObjectType: "organization", ObjectID: org.ID,
			Payload: mustJSON(types.RBACMappingsPayload{OrgID: org.ID, Changes: changes}),
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, org.ID, types.EventRBACMappingsUpdated, types.RBACMappingsPayload{
			OrgID: org.ID, Changes: changes,
		})
	})
	if err != nil {
		return nil, err
	}
	return changes, nil
}

// rolePermissions loads a role's permission bundle by ID.
func (s *Service) rolePermissions(ctx context.Context, q db.Querier, orgID, roleID string) ([]string, error) {
	role, err := s.store.GetRoleByID(ctx, q, orgID, roleID)
	if err != nil {
		return nil, err
	}
	return role.Permissions, nil
}

func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return raw
}

// CreateIdentityClient inserts the metadata projection row.
func (s *Store) CreateIdentityClient(ctx context.Context, q db.Querier, c *types.IdentityClient) error {
	const sql = `INSERT INTO identity_clients (org_id, client_id, name, type, audiences, scopes, redirect_uris, status)
	             VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING created_at`
	err := q.QueryRow(ctx, sql, c.OrgID, c.ClientID, c.Name, c.Type,
		nonEmptyJSON(c.Audiences), nonEmptyJSON(c.Scopes), nonEmptyJSON(c.RedirectURIs), c.Status).
		Scan(&c.CreatedAt)
	if isUniqueViolation(err) {
		return ErrClientNameTaken
	}
	return err
}

func (s *Store) GetIdentityClient(ctx context.Context, q db.Querier, orgID, clientID string) (*types.IdentityClient, error) {
	const sql = `SELECT client_id, org_id, name, type, audiences, scopes, redirect_uris, status, created_at
	             FROM identity_clients WHERE org_id = $1 AND client_id = $2`
	return scanIdentityClient(q.QueryRow(ctx, sql, orgID, clientID))
}

func (s *Store) ListIdentityClients(ctx context.Context, q db.Querier, orgID string) ([]types.IdentityClient, error) {
	const sql = `SELECT client_id, org_id, name, type, audiences, scopes, redirect_uris, status, created_at
	             FROM identity_clients WHERE org_id = $1 ORDER BY created_at`
	rows, err := q.Query(ctx, sql, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.IdentityClient
	for rows.Next() {
		c, err := scanIdentityClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// UpdateIdentityClient rewrites the mutable metadata fields.
func (s *Store) UpdateIdentityClient(ctx context.Context, q db.Querier, c *types.IdentityClient) error {
	const sql = `UPDATE identity_clients SET name=$3, audiences=$4, scopes=$5, redirect_uris=$6, updated_at=now()
	             WHERE org_id=$1 AND client_id=$2`
	_, err := q.Exec(ctx, sql, c.OrgID, c.ClientID, c.Name,
		nonEmptyJSON(c.Audiences), nonEmptyJSON(c.Scopes), nonEmptyJSON(c.RedirectURIs))
	if isUniqueViolation(err) {
		return ErrClientNameTaken
	}
	return err
}

func (s *Store) SetIdentityClientStatus(ctx context.Context, q db.Querier, orgID, clientID, status string) error {
	const sql = `UPDATE identity_clients SET status=$3, updated_at=now() WHERE org_id=$1 AND client_id=$2`
	_, err := q.Exec(ctx, sql, orgID, clientID, status)
	return err
}

// UpdateTeamRole sets the org role a team grants (RBAC mappings route).
func (s *Store) UpdateTeamRole(ctx context.Context, q db.Querier, teamID, roleID string) error {
	const sql = `UPDATE teams SET role_id=$2 WHERE id=$1`
	_, err := q.Exec(ctx, sql, teamID, roleID)
	return err
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanIdentityClient(row rowScanner) (*types.IdentityClient, error) {
	var c types.IdentityClient
	var audiences, scopes, redirectURIs []byte
	err := row.Scan(&c.ClientID, &c.OrgID, &c.Name, &c.Type, &audiences, &scopes, &redirectURIs, &c.Status, &c.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrClientNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(audiences, &c.Audiences); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(scopes, &c.Scopes); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(redirectURIs, &c.RedirectURIs); err != nil {
		return nil, err
	}
	return &c, nil
}

func nonEmptyJSON(items []string) []byte {
	if len(items) == 0 {
		return []byte("[]")
	}
	raw, _ := json.Marshal(items)
	return raw
}
