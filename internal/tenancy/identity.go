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

// SetRBACMappings applies the declarative team → role mapping set
// atomically: every mapping is validated first, then all role changes land
// in one TX with a single audit row and one outbox event driving the
// OpenFGA tuple rewrite.
func (s *Service) SetRBACMappings(ctx context.Context, actor, slug string, mappings []types.TeamRoleMapping) ([]types.TeamRoleChange, error) {
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return nil, err
	}
	// Validate everything before touching the DB so a bad entry fails the
	// whole request with no partial writes.
	teams := make(map[string]*types.Team, len(mappings))
	for _, m := range mappings {
		if !m.Role.Valid() {
			return nil, fmt.Errorf("tenancy: invalid role %q", m.Role)
		}
		team, err := s.store.GetTeamByName(ctx, s.db.Pool, org.ID, m.Team)
		if err != nil {
			return nil, err
		}
		teams[m.Team] = team
	}
	var changes []types.TeamRoleChange
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		for _, m := range mappings {
			team := teams[m.Team]
			if team.Role == m.Role {
				continue
			}
			if err := s.store.UpdateTeamRole(ctx, tx, team.ID, m.Role); err != nil {
				return err
			}
			changes = append(changes, types.TeamRoleChange{
				TeamID: team.ID, Name: team.Name, OldRole: team.Role, NewRole: m.Role,
			})
		}
		if len(changes) == 0 {
			return nil
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
func (s *Store) UpdateTeamRole(ctx context.Context, q db.Querier, teamID string, role types.Role) error {
	const sql = `UPDATE teams SET role=$2 WHERE id=$1`
	_, err := q.Exec(ctx, sql, teamID, role)
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
