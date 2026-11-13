package agentgateway

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"
	extensionsv1 "github.com/7K-Inari/inari-api/gen/go/inari/extensions/v1"
	"github.com/7K-Inari/inari-api/gen/go/inari/extensions/v1/extensionsv1connect"

	"github.com/7K-Inari/inari-server/internal/types"
)

// Extension-gateway tunnel (plan §5.3 imperative ops / §5.8): extensions call
// the control plane to run one imperative action on a tenant cluster and wait
// for the result. The canonical inari-api inari.extensions.v1.AgentGateway
// contract carries agentv1.InvokeAction and returns agentv1.CommandAck.
//
// Authentication is per-extension identity (ADR-0008): the extension backend
// presents a client_credentials JWT (Authorization: Bearer) minted for its
// dedicated Keycloak service-account client; the ExtensionAuthenticator
// resolves it to the registry row. The hop from the extension backend to the
// gateway is platform-internal machine traffic (the end user was already
// authenticated + authorized by the extension proxy at /api/extensions/<name>/*).
const (
	// ExtensionInvokeProcedure is the generated AgentGateway InvokeAction path.
	ExtensionInvokeProcedure = extensionsv1connect.AgentGatewayInvokeActionProcedure
	// MetadataTenant/MetadataCluster route the command to a cluster.
	MetadataTenant  = extensionsv1.MetadataTenant
	MetadataCluster = extensionsv1.MetadataCluster
	// MetadataUserCredentialRef carries the opaque per-user credential
	// reference the agent redeems via AgentCredentials.RedeemUserCredential
	// (agent.v1 InvokeAction.user_credential_ref). The command journal is
	// persisted, so only this reference ever crosses the hop — raw user
	// tokens are rejected, never stored in agent_commands.payload.
	MetadataUserCredentialRef = extensionsv1.MetadataUserCredentialRef
	// MetadataUserCredential carries a raw per-user token from the extension
	// hop (in memory only). The gateway mints a vault ref for it and the
	// command payload carries only that ref — the token is never persisted,
	// logged, or audited.
	MetadataUserCredential = extensionsv1.MetadataUserCredential
	defaultInvokeWait      = 60 * time.Second
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

type extensionService struct {
	gateway *Gateway
	auth    ExtensionAuthenticator
	wait    time.Duration
}

// InvokeAction implements the generated inari.extensions.v1.AgentGateway
// handler. Metadata is read from the generated Connect call context.
func (s *extensionService) InvokeAction(ctx context.Context, req *agentv1.InvokeAction) (*agentv1.CommandAck, error) {
	info, ok := connect.CallInfoForServerContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeInternal, "missing RPC call info")
	}
	return s.gateway.invokeExtension(ctx, req, httpHeader(info.RequestHeader()), s.auth, s.wait)
}

// ExtensionInvokeService returns the generated AgentGateway implementation, or
// nil when no authenticator is wired (feature off).
func (g *Gateway) ExtensionInvokeService(auth ExtensionAuthenticator, wait time.Duration) extensionsv1connect.AgentGatewayHandler {
	if auth == nil {
		return nil
	}
	if wait <= 0 {
		wait = defaultInvokeWait
	}
	return &extensionService{gateway: g, auth: auth, wait: wait}
}

// ExtensionInvokeHandler is a generated-handler HTTP wrapper used by focused
// integration tests. Production mounts ExtensionInvokeService by service name.
func (g *Gateway) ExtensionInvokeHandler(auth ExtensionAuthenticator, wait time.Duration) (string, http.Handler) {
	svc := g.ExtensionInvokeService(auth, wait)
	if svc == nil {
		return "", nil
	}
	server := connect.NewServer()
	extensionsv1connect.RegisterAgentGatewayHandler(server, svc)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server)
	return ExtensionInvokeProcedure, mux
}

// httpHeader copies a connect.Header into an http.Header for the
// ExtensionAuthenticator contract (which predates connect v2).
func httpHeader(h *connect.Header) http.Header {
	out := make(http.Header, h.Len())
	for k, vs := range h.All() {
		out[k] = append(out[k], vs...)
	}
	return out
}

// invokeExtension authenticates the extension, routes the command to the
// cluster, and waits for the agent's ack. The RPC metadata headers arrive
// explicitly because connect v2 offers no test seam for injecting a
// server-side CallInfo into a context.
func (g *Gateway) invokeExtension(ctx context.Context, req *agentv1.InvokeAction, header http.Header, auth ExtensionAuthenticator, wait time.Duration) (*agentv1.CommandAck, error) {
	ext, err := auth.AuthenticateExtension(ctx, header)
	if err != nil {
		return nil, err
	}
	orgID := header.Get(MetadataTenant)
	clusterID := header.Get(MetadataCluster)
	// Org binding: an org-scoped extension may only invoke within its own
	// tenant; platform-global extensions are unbound (ADR-0008).
	if ext.OrgID != "" && ext.OrgID != orgID {
		return nil, connect.Errorf(connect.CodePermissionDenied, "extension may not invoke in this tenant")
	}
	if orgID == "" || clusterID == "" {
		return nil, connect.Errorf(connect.CodeInvalidArgument, "%s and %s metadata required", MetadataTenant, MetadataCluster)
	}
	cluster, err := g.registry.GetCluster(ctx, clusterID)
	if err != nil {
		return nil, connect.Errorf(connect.CodeNotFound, "cluster not found")
	}
	if cluster.OrgID != orgID {
		return nil, connect.Errorf(connect.CodePermissionDenied, "cluster does not belong to tenant")
	}
	if cluster.State != types.ClusterStateActive {
		return nil, connect.Errorf(connect.CodeFailedPrecondition, "cluster is %s, not active", cluster.State)
	}
	// Per-user credential reference (W2 auth model): the control plane owns
	// InvokeAction.user_credential_ref — the extension hop supplies it via
	// metadata; any value self-asserted in the payload is discarded. Raw
	// user tokens are rejected outright in the ref header.
	credRef := header.Get(MetadataUserCredentialRef)
	req.UserCredentialRef = ""
	if credRef != "" {
		if err := validateUserCredentialRef(credRef); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err.Error()).WithCause(err)
		}
	}
	// The control plane owns the command journal id: stamp it into the
	// payload — the agent's dispatcher dedupes/acks on
	// InvokeAction.CommandId, and its ack must match our journal row.
	req.CommandId = uuid.NewString()
	// Raw user token over the hop (W3): the vault mints a credential bound
	// to this command and cluster with a TTL equal to the invoke wait; the
	// persisted payload carries only the minted ref. The credential and the
	// command row commit atomically (command_id FK).
	rawToken := header.Get(MetadataUserCredential)
	if rawToken != "" {
		if credRef != "" {
			return nil, connect.Errorf(connect.CodeInvalidArgument,
				"%s and %s are mutually exclusive", MetadataUserCredential, MetadataUserCredentialRef)
		}
		if g.vault == nil {
			return nil, connect.Errorf(connect.CodeFailedPrecondition,
				"user credential vault not configured")
		}
		credRef = g.vault.NewRef()
	}
	if credRef != "" {
		req.UserCredentialRef = credRef
	}
	// Imperative operations fail closed before enqueue/audit when no outbound
	// agent stream can accept the command. Input and vault validation above
	// retain their specific errors; other command queues are unchanged.
	if !g.hasLiveSession(clusterID) {
		return nil, connect.Errorf(connect.CodeUnavailable, "no connected agent for cluster %q", clusterID)
	}
	anyPayload, err := anypb.New(req)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err.Error()).WithCause(err)
	}
	raw, err := protojson.Marshal(anyPayload)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err.Error()).WithCause(err)
	}
	// Audit attribution (ADR-0008): every tunneled action is attributable to
	// the extension's own identity before it is queued.
	if err := g.audit.Record(ctx, g.db.Pool, &types.AuditEvent{
		OrgID: orgID, Actor: ext.ClientID, Action: "extension.action_invoked",
		ObjectType: "cluster", ObjectID: clusterID,
		Payload: []byte(fmt.Sprintf(`{"extension":%q,"action":%q,"commandId":%q,"userCredential":%t}`,
			ext.Name, req.Action, req.CommandId, req.UserCredentialRef != "")),
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("audit: %w", err).Error())
	}
	cmd := &types.AgentCommand{
		ID:        req.CommandId,
		ClusterID: clusterID,
		Type:      agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_INVOKE_ACTION),
		Payload:   raw,
	}
	if rawToken != "" {
		// Atomic: command row first (command_id FK), then the credential.
		tx, err := g.db.Pool.Begin(ctx)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("enqueue: %w", err).Error())
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `INSERT INTO agent_commands (id, cluster_id, type, payload)
			VALUES ($1,$2,$3,$4) ON CONFLICT (id) DO NOTHING`,
			cmd.ID, cmd.ClusterID, cmd.Type, cmd.Payload); err != nil {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("enqueue: %w", err).Error())
		}
		if err := g.vault.MintWithRefTx(ctx, tx, credRef, clusterID, cmd.ID, []byte(rawToken), wait); err != nil {
			return nil, connect.Errorf(connect.CodeInternal, "mint user credential")
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("enqueue: %w", err).Error())
		}
	} else if err := g.queue.Enqueue(ctx, cmd); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("enqueue: %w", err).Error())
	}
	ack, err := g.awaitAck(ctx, cmd.ClusterID, cmd.ID, wait)
	if err != nil {
		return nil, err
	}
	return ack, nil
}

// awaitAck polls the command journal until the agent acks (or the wait
// expires). The dispatch loop delivers at-least-once; the agent is
// idempotent on command id.
func (g *Gateway) awaitAck(ctx context.Context, clusterID, commandID string, wait time.Duration) (*agentv1.CommandAck, error) {
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
		if !g.hasLiveSession(clusterID) {
			return nil, connect.Errorf(connect.CodeUnavailable, "agent disconnected while awaiting command %q", commandID)
		}
		if time.Now().After(deadline) {
			return nil, connect.Errorf(connect.CodeDeadlineExceeded, "agent did not ack within %s (offline?)", wait)
		}
		select {
		case <-ctx.Done():
			return nil, connect.NewError(connect.CodeCanceled, ctx.Err().Error())
		case <-time.After(500 * time.Millisecond):
		}
	}
}
