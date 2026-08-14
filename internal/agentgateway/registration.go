package agentgateway

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"

	"github.com/7K-Inari/inari-server/internal/clusterregistry"
	"github.com/7K-Inari/inari-server/internal/types"
)

// RegistrationService implements inari.agent.v1.RegistrationService: the
// one-time bootstrap exchange (plan §5.3 step 1). Unauthenticated except for
// the registration token itself.
func (g *Gateway) RegisterCluster(ctx context.Context, req *connect.Request[agentv1.RegisterClusterRequest]) (*connect.Response[agentv1.RegisterClusterResponse], error) {
	if req.Msg.RegistrationToken == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("registration_token required"))
	}
	cluster, err := g.registry.ConsumeRegistrationToken(ctx, req.Msg.RegistrationToken)
	switch {
	case errors.Is(err, clusterregistry.ErrTokenInvalid):
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	case errors.Is(err, clusterregistry.ErrTokenUsed):
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, clusterregistry.ErrTokenExpired):
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("consume token: %w", err))
	}

	switch cluster.State {
	case types.ClusterStateRevoked:
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("cluster is revoked"))
	case types.ClusterStatePendingApproval:
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("cluster enrollment pending approval"))
	}

	clientID, err := g.clients.CreateClusterClient(ctx, cluster.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("provision identity: %w", err))
	}
	labels := cluster.Labels
	if len(req.Msg.ClusterLabels) > 0 {
		labels = req.Msg.ClusterLabels
	}
	if err := g.registry.MarkRegistered(ctx, "agent:"+cluster.ID, cluster.ID, clientID,
		req.Msg.KubernetesVersion, labels); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("mark registered: %w", err))
	}

	res := connect.NewResponse(&agentv1.RegisterClusterResponse{
		ClusterId:     cluster.ID,
		OidcIssuerUrl: g.cfg.OIDCIssuerURL,
		ClientId:      clientID,
		ClientSecretDelivery: &agentv1.SecretDeliveryReference{
			EsoSecretStore:  g.cfg.ESOSecretStore,
			SecretName:      g.cfg.ESOSecretName,
			SecretNamespace: g.cfg.ESOSecretNamespace,
			SecretKey:       g.cfg.ESOSecretKey,
		},
		CredentialsExpireHint: timestamppb.Now(),
	})
	return res, nil
}
