package agentgateway

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
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
func (h *CredentialsHandler) RedeemUserCredential(ctx context.Context, req *connect.Request[agentv1.RedeemUserCredentialRequest]) (*connect.Response[agentv1.RedeemUserCredentialResponse], error) {
	id := AgentIdentityFromContext(ctx)
	if id == nil || id.ClusterID == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("missing cluster identity"))
	}
	ref := req.Msg.GetCredentialRef()
	if ref == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("credential_ref required"))
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
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("credential not found"))
	case errors.Is(err, ErrCredentialExpired):
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("credential expired"))
	case errors.Is(err, ErrCredentialClusterMismatch):
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("credential not bound to this cluster"))
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("redeem credential"))
	}
	return connect.NewResponse(&agentv1.RedeemUserCredentialResponse{
		BearerToken: string(token),
		ExpiresAt:   timestamppb.New(expiresAt),
	}), nil
}
