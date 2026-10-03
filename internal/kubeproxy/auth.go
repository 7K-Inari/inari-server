package kubeproxy

import (
	"context"
	"fmt"
	"strings"

	"connectrpc.com/connect"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/tenancy"
)

// agentIdentityKey carries the validated tunnel-agent identity through the
// Connect handler context (mirrors agentgateway's stream interceptor).
type agentIdentityKey struct{}

// AgentIdentityFromContext returns the authenticated tunnel-agent identity,
// or nil.
func AgentIdentityFromContext(ctx context.Context) *authn.Identity {
	id, _ := ctx.Value(agentIdentityKey{}).(*authn.Identity)
	return id
}

// AgentAuthInterceptor authenticates tunnel-agent streams: a bearer
// client-credentials JWT with a hardcoded cluster_id claim, minted for the
// per-cluster client tunnel-<cluster-id> (azp must match). Mirrors
// agentgateway.AuthInterceptor with the added azp pinning.
func AgentAuthInterceptor(v authn.Validator) connect.Interceptor {
	return &agentAuthInterceptor{v: v}
}

type agentAuthInterceptor struct{ v authn.Validator }

func (i *agentAuthInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		id, err := i.authenticate(ctx, req.Header().Get("Authorization"))
		if err != nil {
			return nil, err
		}
		return next(context.WithValue(ctx, agentIdentityKey{}, id), req)
	}
}

func (i *agentAuthInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (i *agentAuthInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		id, err := i.authenticate(ctx, conn.RequestHeader().Get("Authorization"))
		if err != nil {
			return err
		}
		return next(context.WithValue(ctx, agentIdentityKey{}, id), conn)
	}
}

func (i *agentAuthInterceptor) authenticate(ctx context.Context, header string) (*authn.Identity, error) {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("missing bearer token"))
	}
	id, err := i.v.Validate(ctx, header[len(prefix):])
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid token"))
	}
	if id.ClusterID == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("token has no cluster_id claim"))
	}
	// The token must be minted for this cluster's own tunnel client —
	// never a self-asserted identity (plan §7.2 security model 3).
	if id.AuthorizedParty != tenancy.TunnelClientID(id.ClusterID) {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("token azp does not match the cluster tunnel client"))
	}
	return id, nil
}
