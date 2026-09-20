package agentgateway

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"

	"github.com/7K-Inari/inari-server/internal/types"
)

// Extension-gateway tunnel (plan §5.3 imperative ops / §5.8): extensions call
// the control plane to run one imperative action on a tenant cluster and wait
// for the result. The reference contract is the protojson-over-gRPC method
//
//	/inari.extensions.v1.AgentGateway/InvokeAction
//
// request: agentv1.InvokeAction, response: agentv1.CommandAck, with tenant and
// cluster carried in the x-inari-tenant / x-inari-cluster metadata headers
// (contract defined by 7K-Inari/inari-ext-argocd, the reference extension).
//
// The handler is mounted only when INARI_EXTENSION_GATEWAY_TOKEN is set and
// callers must present it in the x-inari-extension-token header: the hop from
// the extension backend to the gateway is platform-internal machine traffic
// (the end user was already authenticated + authorized by the extension proxy
// at /api/extensions/<name>/*). A per-extension identity model replaces the
// shared token in the production design.
const (
	// ExtensionInvokeProcedure is the full gRPC method path.
	ExtensionInvokeProcedure = "/inari.extensions.v1.AgentGateway/InvokeAction"
	// MetadataTenant/MetadataCluster route the command to a cluster.
	MetadataTenant    = "x-inari-tenant"
	MetadataCluster   = "x-inari-cluster"
	headerExtToken    = "x-inari-extension-token"
	defaultInvokeWait = 60 * time.Second
)

// ExtensionInvokeHandler returns the ConnectRPC handler for the extension
// tunnel, or nil when the shared gate token is not configured (feature off).
// clusterLookup resolves clusters; queue receives the command and the handler
// polls it until the agent's CommandAck lands (the stream's dispatch/ack loop
// does the transport).
func (g *Gateway) ExtensionInvokeHandler(token string, wait time.Duration) (string, http.Handler) {
	if token == "" {
		return "", nil
	}
	if wait <= 0 {
		wait = defaultInvokeWait
	}
	fn := func(ctx context.Context, req *connect.Request[agentv1.InvokeAction]) (*connect.Response[agentv1.CommandAck], error) {
		return g.invokeExtension(ctx, req, token, wait)
	}
	return ExtensionInvokeProcedure, connect.NewUnaryHandler(ExtensionInvokeProcedure, fn)
}

// invokeExtension authenticates the extension, routes the command to the
// cluster, and waits for the agent's ack.
func (g *Gateway) invokeExtension(ctx context.Context, req *connect.Request[agentv1.InvokeAction], token string, wait time.Duration) (*connect.Response[agentv1.CommandAck], error) {
	if req.Header().Get(headerExtToken) != token {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("extension gateway token missing or invalid"))
	}
	orgID := req.Header().Get(MetadataTenant)
	clusterID := req.Header().Get(MetadataCluster)
	if orgID == "" || clusterID == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("%s and %s metadata required", MetadataTenant, MetadataCluster))
	}
	cluster, err := g.registry.GetCluster(ctx, clusterID)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("cluster not found"))
	}
	if cluster.OrgID != orgID {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("cluster does not belong to tenant"))
	}
	if cluster.State != types.ClusterStateActive {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("cluster is %s, not active", cluster.State))
	}
	anyPayload, err := anypb.New(req.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	raw, err := protojson.Marshal(anyPayload)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	cmd := &types.AgentCommand{
		ID:        uuid.NewString(),
		ClusterID: clusterID,
		Type:      agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_INVOKE_ACTION),
		Payload:   raw,
	}
	if err := g.queue.Enqueue(ctx, cmd); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("enqueue: %w", err))
	}
	ack, err := g.awaitAck(ctx, cmd.ID, wait)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(ack), nil
}

// awaitAck polls the command journal until the agent acks (or the wait
// expires). The dispatch loop delivers at-least-once; the agent is
// idempotent on command id.
func (g *Gateway) awaitAck(ctx context.Context, commandID string, wait time.Duration) (*agentv1.CommandAck, error) {
	deadline := time.Now().Add(wait)
	for {
		cmd, err := g.queue.Get(ctx, commandID)
		if err == nil {
			switch cmd.Status {
			case types.CommandStatusAcked:
				return &agentv1.CommandAck{CommandId: commandID, Result: agentv1.CommandResult_COMMAND_RESULT_APPLIED, Message: cmd.ResultMessage}, nil
			case types.CommandStatusNacked:
				return &agentv1.CommandAck{CommandId: commandID, Result: agentv1.CommandResult_COMMAND_RESULT_FAILED, Message: cmd.ResultMessage}, nil
			}
		}
		if time.Now().After(deadline) {
			return nil, connect.NewError(connect.CodeDeadlineExceeded, fmt.Errorf("agent did not ack within %s (offline?)", wait))
		}
		select {
		case <-ctx.Done():
			return nil, connect.NewError(connect.CodeCanceled, ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
}
