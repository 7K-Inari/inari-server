package agentgateway

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"

	"github.com/7K-Inari/inari-server/internal/clusterdex"
	"github.com/7K-Inari/inari-server/internal/clusterregistry"
	"github.com/7K-Inari/inari-server/internal/featureflags"
	"github.com/7K-Inari/inari-server/internal/secrets"
	"github.com/7K-Inari/inari-server/internal/types"
)

// TunnelSecretKey is the key under which the tunnel-<id> client secret is
// stored next to the agent client secret in the cluster's ESO secret (plan
// §7.2 — same delivery mechanism, second key).
const TunnelSecretKey = "tunnel-client-secret"

// RegistrationService implements inari.agent.v1.RegistrationService: the
// one-time bootstrap exchange (plan §5.3 step 1). Unauthenticated except for
// the registration token itself.
func (g *Gateway) RegisterCluster(ctx context.Context, req *agentv1.RegisterClusterRequest) (*agentv1.RegisterClusterResponse, error) {
	if req.RegistrationToken == "" {
		return nil, connect.Errorf(connect.CodeInvalidArgument, "registration_token required")
	}
	cluster, err := g.peekToken(ctx, req.RegistrationToken)
	if err != nil {
		return nil, err
	}

	// External side effects run BEFORE the token is burned: a failure leaves
	// the token consumable so the agent retries with backoff instead of
	// waiting for a secret that never arrives (the old ~2min deadline).
	clientID, err := g.clients.CreateClusterClient(ctx, cluster.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("provision identity: %w", err).Error())
	}
	// Track the client's desired state as a platform resource. Pre-token-burn
	// so a failure keeps the token consumable and the agent retries.
	// Render cutover (operator sunset Phase 1): when live, the
	// provider-keycloak TenantClient claim is ALSO rendered + committed to
	// the hub-facing platform repo (dual-run: the desired-state row stays so
	// the resources view keeps listing the client and W2-4 can compare).
	if g.platform != nil {
		if _, err := g.platform.RenderKeycloakClientClaim(ctx, cluster.OrgID, cluster.ID, clientID, g.cfg.OIDCIssuerURL); err != nil {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("render client claim: %w", err).Error())
		}
		desired, _ := json.Marshal(map[string]string{"clientId": clientID, "clusterId": cluster.ID})
		if _, err := g.platform.EnsureDesired(ctx, cluster.OrgID, types.PlatformKindKeycloakClient, clientID, desired); err != nil {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("track client platform resource: %w", err).Error())
		}
	}
	if g.secrets == nil {
		return nil, connect.Errorf(connect.CodeUnavailable,
			"pending_secret_delivery: platform secret store not configured")
	}
	secret, err := g.clients.ClusterClientSecret(ctx, clientID)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, fmt.Errorf("pending_secret_delivery: read client secret: %w", err).Error())
	}
	if err := g.secrets.Put(ctx, secrets.ClusterOIDCPath(cluster.ID), g.cfg.ESOSecretKey, secret); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, fmt.Errorf("pending_secret_delivery: write secret store: %w", err).Error())
	}
	// Kubectl tunnel (plan §7.2): provision the dedicated tunnel-<id> client
	// and deliver its secret alongside the agent's (same ESO secret, second
	// key). Additive: old agents ignore the extra response fields; old
	// servers never send them.
	tunnelClientID, err := g.clients.CreateTunnelClient(ctx, cluster.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("provision tunnel identity: %w", err).Error())
	}
	tunnelSecret, err := g.clients.ClusterClientSecret(ctx, tunnelClientID)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, fmt.Errorf("pending_secret_delivery: read tunnel client secret: %w", err).Error())
	}
	if err := g.secrets.Put(ctx, secrets.ClusterOIDCPath(cluster.ID), TunnelSecretKey, tunnelSecret); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, fmt.Errorf("pending_secret_delivery: write tunnel secret: %w", err).Error())
	}
	// Dex SSO baseline (operator sunset Phase 2, decision D5): provision the
	// per-cluster Dex-federation client (cluster-<id>-dex) and deliver the
	// Dex config.yaml + ArgoCD static-client secret via the same Vault/ESO
	// seam. Pre-token-burn like the other side effects; gated by the
	// cluster_dex.fanout kill-switch.
	if g.dexProvisioningEnabled(ctx, cluster.ID) {
		if err := g.provisionDex(ctx, cluster); err != nil {
			return nil, err
		}
	}
	// The client is provisioned + its secret delivered: the control plane is
	// the source of truth for this resource (no operator CR is rendered for
	// keycloak-client rows), so mark it ready here.
	if g.platform != nil {
		if err := g.platform.MarkProvisioned(ctx, cluster.OrgID, types.PlatformKindKeycloakClient, clientID,
			"oidc client provisioned via keycloak admin api"); err != nil {
			slog.Warn("agentgateway: mark keycloak-client provisioned", "cluster", cluster.ID, "error", err)
		}
	}

	cluster, err = g.consumeToken(ctx, req.RegistrationToken)
	if err != nil {
		return nil, err
	}
	labels := cluster.Labels
	if len(req.ClusterLabels) > 0 {
		labels = req.ClusterLabels
	}
	if err := g.registry.MarkRegistered(ctx, "agent:"+cluster.ID, cluster.ID, clientID,
		req.KubernetesVersion, req.AgentVersion, labels); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("mark registered: %w", err).Error())
	}

	// The ESO store name comes from the secret-stores registry when wired,
	// falling back to the configured default (pre-registry deployments).
	esoStore := g.cfg.ESOSecretStore
	if g.storeLookup != nil {
		if name, err := g.storeLookup.PlatformStoreName(ctx, esoStore); err == nil {
			esoStore = name
		}
	}
	res := &agentv1.RegisterClusterResponse{
		ClusterId:     cluster.ID,
		OidcIssuerUrl: g.cfg.OIDCIssuerURL,
		ClientId:      clientID,
		ClientSecretDelivery: &agentv1.SecretDeliveryReference{
			EsoSecretStore:  esoStore,
			SecretName:      g.cfg.ESOSecretName,
			SecretNamespace: g.cfg.ESOSecretNamespace,
			SecretKey:       g.cfg.ESOSecretKey,
		},
		TunnelClientId: tunnelClientID,
		TunnelClientSecretDelivery: &agentv1.SecretDeliveryReference{
			EsoSecretStore:  esoStore,
			SecretName:      g.cfg.ESOSecretName,
			SecretNamespace: g.cfg.ESOSecretNamespace,
			SecretKey:       TunnelSecretKey,
		},
		CredentialsExpireHint: timestamppb.Now(),
	}
	// Feature A: resolve the cluster's bound baseline repo from the
	// tenant_git_repos registry. Empty when unbound (pre-Feature-A orgs).
	if g.baselineRepos != nil {
		if repo, err := g.baselineRepos.BaselineRepo(ctx, cluster.ID); err == nil {
			res.BaselineRepo = repo
		} else {
			slog.Warn("agentgateway: baseline repo lookup failed", "cluster", cluster.ID, "error", err)
		}
	}
	return res, nil
}

// dexProvisioningEnabled reports whether the Dex fan-out kill-switch is on
// (nil flags = registered default: on).
func (g *Gateway) dexProvisioningEnabled(ctx context.Context, clusterID string) bool {
	return g.flags == nil || g.flags.Bool(ctx, featureflags.KeyClusterDexFanout, clusterID)
}

// provisionDex provisions the cluster-<id>-dex Keycloak client and delivers
// the Dex config.yaml (Keycloak connector + argocd static client) and the
// static-client secret to the cluster's Vault path. The rendered appsets
// reference only the ESO-secret names/keys; this Vault write is the single
// place secret material enters the delivery path.
func (g *Gateway) provisionDex(ctx context.Context, cluster *types.Cluster) error {
	issuer := clusterdex.DefaultIssuerURL(cluster.ID)
	dexClientID, dexSecret, err := g.clients.CreateClusterDexClient(ctx, cluster.ID, issuer, nil)
	if err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("provision dex identity: %w", err).Error())
	}
	// Keep an already-delivered static secret stable across re-registrations:
	// rotating it would desync ArgoCD's ESO-synced client secret from the
	// running Dex (which reads config.yaml only at startup) until the next
	// Dex restart — an SSO outage window on a mere label change.
	staticSecret, err := g.stableStaticSecret(ctx, secrets.ClusterOIDCPath(cluster.ID))
	if err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("provision dex static secret: %w", err).Error())
	}
	configYAML, err := clusterdex.RenderDexConfig(clusterdex.DexConfigInput{
		Issuer:             issuer,
		KeycloakIssuerURL:  g.cfg.OIDCIssuerURL,
		ClientID:           dexClientID,
		ClientSecret:       dexSecret,
		ArgoCDStaticSecret: staticSecret,
	})
	if err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("render dex config: %w", err).Error())
	}
	path := secrets.ClusterOIDCPath(cluster.ID)
	if err := g.secrets.Put(ctx, path, clusterdex.VaultKeyDexConfigYAML, string(configYAML)); err != nil {
		return connect.NewError(connect.CodeUnavailable, fmt.Errorf("pending_secret_delivery: write dex config: %w", err).Error())
	}
	if err := g.secrets.Put(ctx, path, clusterdex.VaultKeyArgoCDClientSecret, staticSecret); err != nil {
		return connect.NewError(connect.CodeUnavailable, fmt.Errorf("pending_secret_delivery: write dex argocd secret: %w", err).Error())
	}
	return nil
}

// stableStaticSecret returns the cluster's existing Dex static-client
// secret when one was already delivered, or generates a fresh one. A read
// failure is NOT fall-backed to regeneration (that would silently rotate on
// a Vault read outage) — the registration fails and retries instead.
func (g *Gateway) stableStaticSecret(ctx context.Context, path string) (string, error) {
	existing, found, err := g.secrets.Get(ctx, path, clusterdex.VaultKeyArgoCDClientSecret)
	if err != nil {
		return "", fmt.Errorf("read back dex argocd secret: %w", err)
	}
	if found && existing != "" {
		return existing, nil
	}
	return newStaticSecret()
}

// newStaticSecret generates the Dex static-client secret ArgoCD
// authenticates with (256-bit, base64url).
func newStaticSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (g *Gateway) peekToken(ctx context.Context, token string) (*types.Cluster, error) {
	cluster, err := g.registry.PeekRegistrationToken(ctx, token)
	return cluster, g.tokenErr(err)
}

func (g *Gateway) consumeToken(ctx context.Context, token string) (*types.Cluster, error) {
	cluster, err := g.registry.ConsumeRegistrationToken(ctx, token)
	return cluster, g.tokenErr(err)
}

func (g *Gateway) tokenErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, clusterregistry.ErrTokenInvalid):
		return connect.NewError(connect.CodeUnauthenticated, err.Error()).WithCause(err)
	case errors.Is(err, clusterregistry.ErrTokenUsed):
		return connect.NewError(connect.CodeFailedPrecondition, err.Error()).WithCause(err)
	case errors.Is(err, clusterregistry.ErrTokenExpired):
		return connect.NewError(connect.CodeFailedPrecondition, err.Error()).WithCause(err)
	case errors.Is(err, clusterregistry.ErrClusterRevoked):
		return connect.Errorf(connect.CodePermissionDenied, "cluster is revoked")
	case errors.Is(err, clusterregistry.ErrClusterNotPending):
		return connect.Errorf(connect.CodeFailedPrecondition, "cluster enrollment pending approval")
	default:
		return connect.NewError(connect.CodeInternal, fmt.Errorf("consume token: %w", err).Error())
	}
}
