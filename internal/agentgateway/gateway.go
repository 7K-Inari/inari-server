// Package agentgateway implements the Agent Gateway module (plan §5.2):
// Connect-RPC stream termination per the inari-api M1 protos, per-agent
// command queues with at-least-once delivery, heartbeat, checksum-based
// resync, and the one-time registration exchange. Agent identity always
// comes from the token's hardcoded cluster_id claim — never self-asserted.
package agentgateway

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/capabilities"
	"github.com/7K-Inari/inari-server/internal/clusterregistry"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/secrets"
	"github.com/7K-Inari/inari-server/internal/types"
)

// Config tunes the gateway runtime behavior.
type Config struct {
	PingInterval        time.Duration
	CommandPollInterval time.Duration
	CommandRetryAfter   time.Duration
	// OIDCIssuerURL is advertised to agents at registration.
	OIDCIssuerURL string
	// CurrentAgentVersion is the control plane's supported agent version
	// (N); agents at N and N−1 are supported (plan §11/5). Empty disables
	// the skew check.
	CurrentAgentVersion string
	// ESO delivery reference for the OIDC client secret (plan §5.3) — the
	// secret value itself never transits this API.
	ESOSecretStore     string
	ESOSecretName      string
	ESOSecretNamespace string
	ESOSecretKey       string
}

func (c *Config) withDefaults() Config {
	out := *c
	if out.PingInterval <= 0 {
		out.PingInterval = 30 * time.Second
	}
	if out.CommandPollInterval <= 0 {
		out.CommandPollInterval = time.Second
	}
	if out.CommandRetryAfter <= 0 {
		out.CommandRetryAfter = 30 * time.Second
	}
	if out.ESOSecretName == "" {
		out.ESOSecretName = "inari-agent-oidc-client"
	}
	if out.ESOSecretNamespace == "" {
		out.ESOSecretNamespace = "inari-system"
	}
	if out.ESOSecretKey == "" {
		out.ESOSecretKey = "client-secret"
	}
	return out
}

// Gateway bundles the Agent Gateway dependencies.
type Gateway struct {
	registry   *clusterregistry.Service
	clients    clusterregistry.ClientManager
	caps       *capabilities.Service
	queue      *Queue
	audit      *audit.Store
	db         *db.DB
	cfg        Config
	statusSink StatusSink
	// secrets delivers the OIDC client secret to the platform secret store
	// (ESO path); nil means delivery is unconfigured and registration fails
	// explicitly with CodeUnavailable instead of a false promise.
	secrets secrets.Writer
	// storeLookup resolves the platform ESO SecretStore name from the
	// secret-stores registry (M6.W4); nil means fall back to
	// cfg.ESOSecretStore.
	storeLookup SecretStoreLookup
	// platform records per-cluster keycloak-client desired state (M7.W2);
	// nil means platform-resource tracking is disabled.
	platform PlatformResourceEnsurer
}

// SecretStoreLookup resolves platform-scoped SecretStore names from the
// registry (secretstores.Service seam). ErrNotFound from the registry means
// "keep the configured default".
type SecretStoreLookup interface {
	PlatformStoreName(ctx context.Context, name string) (string, error)
}

// PlatformResourceEnsurer records the desired state of the per-cluster OIDC
// client as a platform-resource row (platformresources.Service seam, M7.W2).
type PlatformResourceEnsurer interface {
	EnsureDesired(ctx context.Context, orgID string, kind types.PlatformResourceKind, name string, desired json.RawMessage) (*types.PlatformResource, error)
}

// WithPlatformResources wires the platform-resources module so cluster
// registration tracks the keycloak-client desired state.
func (g *Gateway) WithPlatformResources(e PlatformResourceEnsurer) *Gateway {
	g.platform = e
	return g
}

// WithSecretStoreLookup wires the registry lookup for the ESO store name
// advertised at registration. Nil-safe: unset keeps the config default.
func (g *Gateway) WithSecretStoreLookup(l SecretStoreLookup) *Gateway {
	g.storeLookup = l
	return g
}

func NewGateway(d *db.DB, registry *clusterregistry.Service, clients clusterregistry.ClientManager,
	caps *capabilities.Service, auditStore *audit.Store, cfg Config) *Gateway {
	c := cfg.withDefaults()
	return &Gateway{
		registry: registry,
		clients:  clients,
		caps:     caps,
		queue:    NewQueue(d, c.CommandRetryAfter),
		audit:    auditStore,
		db:       d,
		cfg:      c,
	}
}

// WithSecretWriter attaches the platform secret-store delivery seam used by
// the registration exchange. Must be set before agents register.
func (g *Gateway) WithSecretWriter(w secrets.Writer) *Gateway {
	g.secrets = w
	return g
}

// Queue exposes the durable command queue for future modules (Orchestrator).
func (g *Gateway) Queue() *Queue { return g.queue }

// StatusSink consumes agent status-update events (Resources Inventory).
type StatusSink interface {
	ApplyStatus(ctx context.Context, clusterID string, upd StatusUpdate) (bool, error)
}

// SetStatusSink wires the inventory module post-construction (nil-safe:
// status updates are drop-and-log until wired).
func (g *Gateway) SetStatusSink(s StatusSink) { g.statusSink = s }

type agentIdentityKey struct{}

// AgentIdentityFromContext returns the authenticated agent identity.
func AgentIdentityFromContext(ctx context.Context) *authn.Identity {
	id, _ := ctx.Value(agentIdentityKey{}).(*authn.Identity)
	return id
}

// AuthInterceptor authenticates agent calls (unary + streaming): bearer JWT
// validated against the platform IdP, and the hardcoded cluster_id claim is
// the agent identity (plan §5.2 — never self-asserted).
func AuthInterceptor(v authn.Validator) connect.Interceptor {
	return &streamAuthInterceptor{v: v}
}

type streamAuthInterceptor struct{ v authn.Validator }

func (i *streamAuthInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		id, err := authenticate(i.v, ctx, req.Header().Get("Authorization"))
		if err != nil {
			return nil, err
		}
		return next(context.WithValue(ctx, agentIdentityKey{}, id), req)
	}
}

func (i *streamAuthInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (i *streamAuthInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		id, err := authenticate(i.v, ctx, conn.RequestHeader().Get("Authorization"))
		if err != nil {
			return err
		}
		return next(context.WithValue(ctx, agentIdentityKey{}, id), conn)
	}
}

func authenticate(v authn.Validator, ctx context.Context, header string) (*authn.Identity, error) {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("missing bearer token"))
	}
	id, err := v.Validate(ctx, header[len(prefix):])
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid token"))
	}
	if id.ClusterID == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("token has no cluster_id claim"))
	}
	return id, nil
}
