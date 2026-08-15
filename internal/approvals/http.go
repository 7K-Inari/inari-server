// HTTP handlers for the approvals module (plan §5.2, basic approvals).
package approvals

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

// TenantResolver resolves a tenant slug to its record (tenancy.Service).
type TenantResolver interface {
	GetTenant(ctx context.Context, slug string) (*types.Organization, error)
}

// Handler exposes the approvals REST surface.
type Handler struct {
	svc     *Service
	tenants TenantResolver
	authz   authz.Authorizer
}

func NewHandler(svc *Service, tenants TenantResolver, az authz.Authorizer) *Handler {
	return &Handler{svc: svc, tenants: tenants, authz: az}
}

// RegisterRoutes mounts the approvals API on the huma API instance.
func (h *Handler) RegisterRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "listApprovals",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/approvals",
		Summary:     "List approval requests (default: pending)",
		Security:    httpserver.SecurityRequirement(),
	}, h.list)

	huma.Register(api, huma.Operation{
		OperationID: "decideApproval",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/approvals/{id}/decide",
		Summary:     "Approve or reject a pending approval request",
		Security:    httpserver.SecurityRequirement(),
	}, h.decide)
}

func (h *Handler) authorizeOrg(ctx context.Context, slug, relation string) (*types.Organization, *authn.Identity, error) {
	id := httpserver.IdentityFromContext(ctx)
	if id == nil {
		return nil, nil, huma.Error401Unauthorized("unauthenticated")
	}
	if !id.MemberOf(slug) {
		return nil, nil, huma.Error403Forbidden("not a member of this organization")
	}
	org, err := h.tenants.GetTenant(ctx, slug)
	if errors.Is(err, tenancy.ErrOrgNotFound) {
		return nil, nil, huma.Error404NotFound("organization not found")
	}
	if err != nil {
		return nil, nil, err
	}
	ok, err := h.authz.Check(ctx, authz.UserObject(id.Subject), relation, authz.OrgObject(org.ID))
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, huma.Error403Forbidden("insufficient permissions")
	}
	return org, id, nil
}

type listInput struct {
	Org   string `path:"org"`
	State string `query:"state" doc:"Filter by state (pending|approved|rejected)"`
}

type listOutput struct {
	Body struct {
		Approvals []types.ApprovalRequest `json:"approvals"`
	}
}

func (h *Handler) list(ctx context.Context, in *listInput) (*listOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	reqs, err := h.svc.List(ctx, org.ID, in.State)
	if err != nil {
		return nil, err
	}
	out := &listOutput{}
	out.Body.Approvals = reqs
	return out, nil
}

type decideInput struct {
	Org  string `path:"org"`
	ID   string `path:"id"`
	Body struct {
		Approve bool   `json:"approve"`
		Reason  string `json:"reason,omitempty"`
	}
}

type decideOutput struct {
	Body struct {
		Approval types.ApprovalRequest `json:"approval"`
	}
}

func (h *Handler) decide(ctx context.Context, in *decideInput) (*decideOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationDeveloper)
	if err != nil {
		return nil, err
	}
	req, err := h.svc.Decide(ctx, org.ID, in.ID, id.Subject, in.Body.Approve, in.Body.Reason)
	if errors.Is(err, ErrNotFound) {
		return nil, huma.Error404NotFound("approval request not found")
	}
	if errors.Is(err, ErrAlreadyDecided) {
		return nil, huma.Error409Conflict("approval request already decided")
	}
	if errors.Is(err, ErrSelfApproval) || errors.Is(err, ErrApproverRole) {
		return nil, huma.Error403Forbidden(err.Error())
	}
	if err != nil {
		return nil, err
	}
	out := &decideOutput{}
	out.Body.Approval = *req
	return out, nil
}
