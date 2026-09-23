// Per-extension identity (ADR-0008, issue #75): every backend extension
// gets a dedicated Keycloak service-account client (clientId ext-<name>,
// client_credentials only, audience inari-extension-gateway) that gates the
// extension-gateway tunnel. The secret is returned exactly once at
// provision/rotate and never persisted — only the client_id projection is
// stored on the extension row. Replaces the interim shared gateway token
// (INARI_EXTENSION_GATEWAY_TOKEN), which gave every extension the same
// principal with no revocation or audit attribution.
package extensionhost

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

// DefaultGatewayAudience is the audience scope every extension client
// carries; the tunnel validator pins it, so a token minted for any other
// purpose (user sessions, agent clients) cannot invoke actions.
const DefaultGatewayAudience = "inari-extension-gateway"

// ErrIdentityNotConfigured is returned when the Keycloak client manager is
// not wired and an identity operation is requested.
var ErrIdentityNotConfigured = errors.New("extensionhost: identity client manager not configured")

// ExtensionClientManager is the Keycloak client CRUD seam the extension
// identity lifecycle needs (implemented by tenancy.KeycloakAdmin; faked in
// tests). Mirrors tenancy.ClientManager without importing the concrete type.
type ExtensionClientManager interface {
	CreateClient(ctx context.Context, spec tenancy.ClientSpec) (secret string, err error)
	RotateClientSecret(ctx context.Context, clientID string) (secret string, err error)
	DisableClient(ctx context.Context, clientID string) error
}

// WithExtensionClientManager wires per-extension identity provisioning:
// Register/Verify ensure a Keycloak client per extension and the rotate
// route regenerates its secret. audience is the scope stamped on each
// client (DefaultGatewayAudience in production).
func (s *Service) WithExtensionClientManager(cm ExtensionClientManager, audience string) *Service {
	if audience == "" {
		audience = DefaultGatewayAudience
	}
	s.clients = cm
	s.gatewayAudience = audience
	return s
}

// ExtensionClientID renders the deterministic Keycloak clientId for an
// extension (registry names are globally unique).
func ExtensionClientID(name string) string {
	return "ext-" + name
}

// ExtensionClientSpec returns the canonical per-extension service-account
// client spec: confidential, service accounts only (no flows, no redirects),
// carrying only the gateway audience scope.
func ExtensionClientSpec(name, audience string) tenancy.ClientSpec {
	return tenancy.ClientSpec{
		ClientID:   ExtensionClientID(name),
		Name:       "extension-" + name,
		ClientType: tenancy.ClientTypeService,
		Audiences:  []string{audience},
		Enabled:    true,
	}
}

// ensureIdentity provisions the extension's Keycloak client when missing
// and persists the client_id projection with audit in one TX. The secret is
// returned exactly once on creation; callers that only need the client to
// exist (lazy ensure at verify) may discard it — rotate regenerates.
// Best-effort DisableClient compensates the external write on TX failure.
func (s *Service) ensureIdentity(ctx context.Context, actor string, e *types.Extension) (string, error) {
	if s.clients == nil {
		return "", ErrIdentityNotConfigured
	}
	if e.ClientID != "" {
		return "", nil // already provisioned
	}
	secret, err := s.clients.CreateClient(ctx, ExtensionClientSpec(e.Name, s.gatewayAudience))
	if err != nil {
		return "", fmt.Errorf("extensionhost: create extension keycloak client: %w", err)
	}
	clientID := ExtensionClientID(e.Name)
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.setClientID(ctx, tx, e.ID, clientID); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: e.OrgID, Actor: actor, Action: "extension.identity.provisioned",
			ObjectType: "extension", ObjectID: e.ID,
			Payload: []byte(fmt.Sprintf(`{"clientId":%q}`, clientID)),
		})
	})
	if err != nil {
		if rbErr := s.clients.DisableClient(ctx, clientID); rbErr != nil {
			return "", fmt.Errorf("extensionhost: %w (rollback keycloak client: %v)", err, rbErr)
		}
		return "", err
	}
	e.ClientID = clientID
	return secret, nil
}

// RotateIdentitySecret regenerates the extension's Keycloak secret and
// returns it exactly once (audited). The old secret is invalidated
// immediately by Keycloak.
func (s *Service) RotateIdentitySecret(ctx context.Context, actor, orgID, id string) (*types.ExtensionCredentials, error) {
	if s.clients == nil {
		return nil, ErrIdentityNotConfigured
	}
	e, err := s.Get(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	if e.ClientID == "" {
		if _, err := s.ensureIdentity(ctx, actor, e); err != nil {
			return nil, err
		}
	}
	secret, err := s.clients.RotateClientSecret(ctx, e.ClientID)
	if err != nil {
		return nil, fmt.Errorf("extensionhost: rotate extension client secret: %w", err)
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "extension.identity.secret_rotated",
			ObjectType: "extension", ObjectID: id,
			Payload: []byte(fmt.Sprintf(`{"clientId":%q}`, e.ClientID)),
		})
	})
	if err != nil {
		return nil, err
	}
	return &types.ExtensionCredentials{ClientID: e.ClientID, Secret: secret}, nil
}

// disableIdentity revokes the extension's Keycloak client (in-flight tokens
// expire on their short TTL). Best-effort: the registry row deletion is the
// authoritative operation, so errors are logged by the caller, not fatal.
func (s *Service) disableIdentity(ctx context.Context, actor string, e *types.Extension) error {
	if s.clients == nil || e.ClientID == "" {
		return nil
	}
	if err := s.clients.DisableClient(ctx, e.ClientID); err != nil {
		return fmt.Errorf("extensionhost: disable extension keycloak client: %w", err)
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: e.OrgID, Actor: actor, Action: "extension.identity.disabled",
			ObjectType: "extension", ObjectID: e.ID,
			Payload: []byte(fmt.Sprintf(`{"clientId":%q}`, e.ClientID)),
		})
	})
}

/* Tunnel authentication ---------------------------------------------------- */

// ExtensionByClientID resolves an extension row by its Keycloak clientId
// (Service seam; faked in tests).
type ExtensionByClientID interface {
	GetByClientID(ctx context.Context, clientID string) (*types.Extension, error)
}

// TunnelAuthenticator authenticates extension-gateway tunnel calls
// (/inari.extensions.v1.AgentGateway/InvokeAction): the extension backend
// presents a client_credentials JWT (Authorization: Bearer) minted for its
// dedicated client; the azp claim resolves the registry row, which must be
// ready. The end user was already authenticated + authorized by the
// extension proxy at /api/extensions/<name>/*.
type TunnelAuthenticator struct {
	exts ExtensionByClientID
	auth authn.Validator
}

// NewTunnelAuthenticator builds the authenticator over a validator pinned
// to the gateway audience (a token for any other audience is rejected).
func NewTunnelAuthenticator(exts ExtensionByClientID, v authn.Validator) *TunnelAuthenticator {
	return &TunnelAuthenticator{exts: exts, auth: v}
}

// AuthenticateExtension resolves the calling extension from the request's
// Bearer token. Errors are connect-coded for the agentgateway handler.
func (a *TunnelAuthenticator) AuthenticateExtension(ctx context.Context, header http.Header) (*types.Extension, error) {
	unauthenticated := func(msg string) (*types.Extension, error) {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New(msg))
	}
	const prefix = "Bearer "
	raw := header.Get("Authorization")
	if len(raw) <= len(prefix) || !strings.EqualFold(raw[:len(prefix)], prefix) {
		return unauthenticated("missing or malformed authorization header")
	}
	id, err := a.auth.Validate(ctx, raw[len(prefix):])
	if err != nil {
		return unauthenticated("invalid token")
	}
	if id.AuthorizedParty == "" {
		return unauthenticated("token has no authorized party (azp)")
	}
	ext, err := a.exts.GetByClientID(ctx, id.AuthorizedParty)
	if err != nil {
		return unauthenticated("unknown extension identity")
	}
	if ext.State != types.ExtensionStateReady {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("extension %s is %s, not ready", ext.Name, ext.State))
	}
	return ext, nil
}
