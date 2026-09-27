package agentgateway

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
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
// Authentication is per-extension identity (ADR-0008): the extension backend
// presents a client_credentials JWT (Authorization: Bearer) minted for its
// dedicated Keycloak service-account client; the ExtensionAuthenticator
// resolves it to the registry row. The hop from the extension backend to the
// gateway is platform-internal machine traffic (the end user was already
// authenticated + authorized by the extension proxy at /api/extensions/<name>/*).
const (
	// ExtensionInvokeProcedure is the full gRPC method path.
	ExtensionInvokeProcedure = "/inari.extensions.v1.AgentGateway/InvokeAction"
	// MetadataTenant/MetadataCluster route the command to a cluster.
	MetadataTenant  = "x-inari-tenant"
	MetadataCluster = "x-inari-cluster"
	// MetadataUserCredentialRef carries the opaque per-user credential
	// reference the agent redeems via AgentCredentials.RedeemUserCredential
	// (agent.v1 InvokeAction.user_credential_ref). The command journal is
	// persisted, so only this reference ever crosses the hop — raw user
	// tokens are rejected, never stored in agent_commands.payload.
	MetadataUserCredentialRef = "x-inari-user-credential-ref"
	defaultInvokeWait         = 60 * time.Second
)

// userCredentialRefMaxLen bounds the opaque reference (it is a lookup key,
// never credential material).
const userCredentialRefMaxLen = 512

var (
	userCredentialRefCharset = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~:/-]*$`)
	// jwtShape matches compact-serialized JWTs (header.payload.signature):
	// belt-and-braces so a confused extension cannot smuggle a raw user token
	// into the persisted command payload.
	jwtShape = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$`)
)

// validateUserCredentialRef enforces the opaque-reference contract.
func validateUserCredentialRef(ref string) error {
	if ref == "" || len(ref) > userCredentialRefMaxLen {
		return fmt.Errorf("invalid %s: empty or over %d bytes", MetadataUserCredentialRef, userCredentialRefMaxLen)
	}
	if !userCredentialRefCharset.MatchString(ref) {
		return fmt.Errorf("invalid %s: illegal characters", MetadataUserCredentialRef)
	}
	if jwtShape.MatchString(ref) {
		return fmt.Errorf("invalid %s: raw tokens are not accepted, only credential references", MetadataUserCredentialRef)
	}
	return nil
}

// ExtensionAuthenticator resolves the calling extension from tunnel request
// metadata (implemented by extensionhost.TunnelAuthenticator; faked in
// tests). Implementations return connect-coded errors.
type ExtensionAuthenticator interface {
	AuthenticateExtension(ctx context.Context, header http.Header) (*types.Extension, error)
}

// ExtensionInvokeHandler returns the ConnectRPC handler for the extension
// tunnel, or nil when no authenticator is wired (feature off). queue
// receives the command and the handler polls it until the agent's
// CommandAck lands (the stream's dispatch/ack loop does the transport).
func (g *Gateway) ExtensionInvokeHandler(auth ExtensionAuthenticator, wait time.Duration) (string, http.Handler) {
	if auth == nil {
		return "", nil
	}
	if wait <= 0 {
		wait = defaultInvokeWait
	}
	fn := func(ctx context.Context, req *connect.Request[agentv1.InvokeAction]) (*connect.Response[agentv1.CommandAck], error) {
		return g.invokeExtension(ctx, req, auth, wait)
	}
	return ExtensionInvokeProcedure, connect.NewUnaryHandler(ExtensionInvokeProcedure, fn)
}

// invokeExtension authenticates the extension, routes the command to the
// cluster, and waits for the agent's ack.
func (g *Gateway) invokeExtension(ctx context.Context, req *connect.Request[agentv1.InvokeAction], auth ExtensionAuthenticator, wait time.Duration) (*connect.Response[agentv1.CommandAck], error) {
	ext, err := auth.AuthenticateExtension(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	orgID := req.Header().Get(MetadataTenant)
	clusterID := req.Header().Get(MetadataCluster)
	// Org binding: an org-scoped extension may only invoke within its own
	// tenant; platform-global extensions are unbound (ADR-0008).
	if ext.OrgID != "" && ext.OrgID != orgID {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("extension may not invoke in this tenant"))
	}
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
	// Per-user credential reference (W2 auth model): the control plane owns
	// InvokeAction.user_credential_ref — the extension hop supplies it via
	// metadata; any value self-asserted in the payload is discarded. Raw
	// user tokens are rejected outright.
	credRef := req.Header().Get(MetadataUserCredentialRef)
	req.Msg.UserCredentialRef = ""
	if credRef != "" {
		if err := validateUserCredentialRef(credRef); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		req.Msg.UserCredentialRef = credRef
	}
	// The control plane owns the command journal id: stamp it into the
	// payload — the agent's dispatcher dedupes/acks on
	// InvokeAction.CommandId, and its ack must match our journal row.
	req.Msg.CommandId = uuid.NewString()
	anyPayload, err := anypb.New(req.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	raw, err := protojson.Marshal(anyPayload)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	// Audit attribution (ADR-0008): every tunneled action is attributable to
	// the extension's own identity before it is queued.
	if err := g.audit.Record(ctx, g.db.Pool, &types.AuditEvent{
		OrgID: orgID, Actor: ext.ClientID, Action: "extension.action_invoked",
		ObjectType: "cluster", ObjectID: clusterID,
		Payload: []byte(fmt.Sprintf(`{"extension":%q,"action":%q,"commandId":%q,"userCredential":%t}`,
			ext.Name, req.Msg.Action, req.Msg.CommandId, req.Msg.UserCredentialRef != "")),
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("audit: %w", err))
	}
	cmd := &types.AgentCommand{
		ID:        req.Msg.CommandId,
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
