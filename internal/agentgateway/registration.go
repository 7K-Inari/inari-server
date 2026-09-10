package agentgateway

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"

	"github.com/7K-Inari/inari-server/internal/clusterregistry"
	"github.com/7K-Inari/inari-server/internal/secrets"
	"github.com/7K-Inari/inari-server/internal/types"
)

// RegistrationService implements inari.agent.v1.RegistrationService: the
// one-time bootstrap exchange (plan §5.3 step 1). Unauthenticated except for
// the registration token itself.
func (g *Gateway) RegisterCluster(ctx context.Context, req *connect.Request[agentv1.RegisterClusterRequest]) (*connect.Response[agentv1.RegisterClusterResponse], error) {
	if req.Msg.RegistrationToken == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("registration_token required"))
	}
	cluster, err := g.peekToken(ctx, req.Msg.RegistrationToken)
	if err != nil {
		return nil, err
	}

	// External side effects run BEFORE the token is burned: a failure leaves
	// the token consumable so the agent retries with backoff instead of
	// waiting for a secret that never arrives (the old ~2min deadline).
	clientID, err := g.clients.CreateClusterClient(ctx, cluster.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("provision identity: %w", err))
	}
	if g.secrets == nil {
		return nil, connect.NewError(connect.CodeUnavailable,
			fmt.Errorf("pending_secret_delivery: platform secret store not configured"))
	}
	secret, err := g.clients.ClusterClientSecret(ctx, clientID)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, fmt.Errorf("pending_secret_delivery: read client secret: %w", err))
	}
	if err := g.secrets.Put(ctx, secrets.ClusterOIDCPath(cluster.ID), g.cfg.ESOSecretKey, secret); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, fmt.Errorf("pending_secret_delivery: write secret store: %w", err))
	}

	cluster, err = g.consumeToken(ctx, req.Msg.RegistrationToken)
	if err != nil {
		return nil, err
	}
	labels := cluster.Labels
	if len(req.Msg.ClusterLabels) > 0 {
		labels = req.Msg.ClusterLabels
	}
	if err := g.registry.MarkRegistered(ctx, "agent:"+cluster.ID, cluster.ID, clientID,
		req.Msg.KubernetesVersion, req.Msg.AgentVersion, labels); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("mark registered: %w", err))
	}

	// The ESO store name comes from the secret-stores registry when wired,
	// falling back to the configured default (pre-registry deployments).
	esoStore := g.cfg.ESOSecretStore
	if g.storeLookup != nil {
		if name, err := g.storeLookup.PlatformStoreName(ctx, esoStore); err == nil {
			esoStore = name
		}
	}
	res := connect.NewResponse(&agentv1.RegisterClusterResponse{
		ClusterId:     cluster.ID,
		OidcIssuerUrl: g.cfg.OIDCIssuerURL,
		ClientId:      clientID,
		ClientSecretDelivery: &agentv1.SecretDeliveryReference{
			EsoSecretStore:  esoStore,
			SecretName:      g.cfg.ESOSecretName,
			SecretNamespace: g.cfg.ESOSecretNamespace,
			SecretKey:       g.cfg.ESOSecretKey,
		},
		CredentialsExpireHint: timestamppb.Now(),
	})
	return res, nil
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
		return connect.NewError(connect.CodeUnauthenticated, err)
	case errors.Is(err, clusterregistry.ErrTokenUsed):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, clusterregistry.ErrTokenExpired):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, clusterregistry.ErrClusterRevoked):
		return connect.NewError(connect.CodePermissionDenied, fmt.Errorf("cluster is revoked"))
	case errors.Is(err, clusterregistry.ErrClusterNotPending):
		return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("cluster enrollment pending approval"))
	default:
		return connect.NewError(connect.CodeInternal, fmt.Errorf("consume token: %w", err))
	}
}
