package agentgateway

import (
	"context"
	"errors"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"
)

// CredentialsHandler implements agentv1connect.AgentCredentialsServiceHandler
// (W1 contract): agents redeem the per-user credential refs carried on
// InvokeAction commands. Mount with AuthInterceptor so the cluster identity
// comes from the token's hardcoded cluster_id claim — never the request.
type CredentialsHandler struct {
	vault *CredentialVault
}

// NewCredentialsHandler wires the handler to the vault.
func NewCredentialsHandler(v *CredentialVault) *CredentialsHandler {
	return &CredentialsHandler{vault: v}
}

// RedeemUserCredential exchanges an opaque credential ref for the user
// token, enforcing cluster binding and single use. Fail closed: missing,
// expired, or cross-cluster refs are typed connect errors; token material
// never appears in errors or logs.
func (h *CredentialsHandler) RedeemUserCredential(ctx context.Context, req *agentv1.RedeemUserCredentialRequest) (*agentv1.RedeemUserCredentialResponse, error) {
	id := AgentIdentityFromContext(ctx)
	if id == nil || id.ClusterID == "" {
		return nil, connect.Errorf(connect.CodeUnauthenticated, "missing cluster identity")
	}
	ref := req.GetCredentialRef()
	if ref == "" {
		return nil, connect.Errorf(connect.CodeInvalidArgument, "credential_ref required")
	}
	token, expiresAt, err := h.vault.Redeem(ctx, ref, id.ClusterID)
	defer func() {
		if token != nil && err != nil {
			// Unreachable today (Redeem returns nil token on error); keep the
			// wipe discipline explicit at the trust boundary.
			for i := range token {
				token[i] = 0
			}
		}
	}()
	switch {
	case errors.Is(err, ErrCredentialNotFound), errors.Is(err, ErrCredentialRedeemed):
		return nil, connect.Errorf(connect.CodeNotFound, "credential not found")
	case errors.Is(err, ErrCredentialExpired):
		return nil, connect.Errorf(connect.CodeFailedPrecondition, "credential expired")
	case errors.Is(err, ErrCredentialClusterMismatch):
		return nil, connect.Errorf(connect.CodePermissionDenied, "credential not bound to this cluster")
	case err != nil:
		return nil, connect.Errorf(connect.CodeInternal, "redeem credential")
	}
	return &agentv1.RedeemUserCredentialResponse{
		BearerToken: string(token),
		ExpiresAt:   timestamppb.New(expiresAt),
	}, nil
}
