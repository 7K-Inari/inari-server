package kubeproxy

import (
	"context"
	"strings"

	"connectrpc.com/connect/v2"

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
// agentgateway.AuthInterceptor with the added azp pinning. In connect v2 the
// interceptor wraps the whole call before unmarshaling, so a header-only
// check rejects unauthenticated streams without any HTTP middleware.
func AgentAuthInterceptor(v authn.Validator) connect.ServerInterceptor {
	i := &agentAuthInterceptor{v: v}
	return func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			var header string
			if info, ok := connect.CallInfoForServerContext(ctx); ok {
				header = info.RequestHeader().Get("Authorization")
			}
			id, err := i.authenticate(ctx, header)
			if err != nil {
				return err
			}
			return next(context.WithValue(ctx, agentIdentityKey{}, id), spec, stream)
		}
	}
}

type agentAuthInterceptor struct{ v authn.Validator }

func (i *agentAuthInterceptor) authenticate(ctx context.Context, header string) (*authn.Identity, error) {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return nil, connect.Errorf(connect.CodeUnauthenticated, "missing bearer token")
	}
	id, err := i.v.Validate(ctx, header[len(prefix):])
	if err != nil {
		return nil, connect.Errorf(connect.CodeUnauthenticated, "invalid token")
	}
	if id.ClusterID == "" {
		return nil, connect.Errorf(connect.CodeUnauthenticated, "token has no cluster_id claim")
	}
	// The token must be minted for this cluster's own tunnel client —
	// never a self-asserted identity (plan §7.2 security model 3).
	if id.AuthorizedParty != tenancy.TunnelClientID(id.ClusterID) {
		return nil, connect.Errorf(connect.CodeUnauthenticated, "token azp does not match the cluster tunnel client")
	}
	return id, nil
}
