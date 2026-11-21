package deploymentplan

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/7K-Inari/inari-server/internal/artifactadmission"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/resourcetargets"
	"github.com/7K-Inari/inari-server/internal/scaffold"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

type TenantResolver interface {
	GetTenant(ctx context.Context, slug string) (*types.Organization, error)
}

type RepoWriteEnforcer interface {
	EnforceRepoWrite(ctx context.Context, id *authn.Identity, orgID, repoID string) error
	EnforceRecordedRepoWrite(ctx context.Context, id *authn.Identity, orgID, instanceID string) error
}

type Handler struct {
	svc       *Service
	tenants   TenantResolver
	authz     authz.Authorizer
	repoWrite RepoWriteEnforcer
}

func NewHandler(svc *Service, tenants TenantResolver, az authz.Authorizer) *Handler {
	return &Handler{svc: svc, tenants: tenants, authz: az}
}

func (h *Handler) WithRepoWriteEnforcement(enforcer RepoWriteEnforcer) *Handler {
	h.repoWrite = enforcer
	return h
}

func (h *Handler) RegisterRoutes(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "preflightDeploymentPlan", Method: http.MethodPost,
		Path: "/api/v1/tenants/{org}/deployment-plans/preflight", Summary: "Normalize a deployment plan and list entitled targets",
		Security: httpserver.SecurityRequirement()}, h.preflight)
	huma.Register(api, huma.Operation{OperationID: "submitDeploymentPlan", Method: http.MethodPost,
		Path: "/api/v1/tenants/{org}/deployment-plans", Summary: "Revalidate and submit a normalized deployment plan",
		Security: httpserver.SecurityRequirement()}, h.submit)
	huma.Register(api, huma.Operation{OperationID: "getDeploymentPlan", Method: http.MethodGet,
		Path: "/api/v1/tenants/{org}/deployment-plans/{id}", Summary: "Get deployment plan and companion state",
		Security: httpserver.SecurityRequirement()}, h.get)
	huma.Register(api, huma.Operation{OperationID: "getInstanceObservability", Method: http.MethodGet,
		Path: "/api/v1/tenants/{org}/instances/{id}/observability", Summary: "Get existing-instance companion readiness and verified links",
		Security: httpserver.SecurityRequirement()}, h.instanceObservability)
}

func (h *Handler) authorize(ctx context.Context, slug, relation string, mutate bool) (*types.Organization, *authn.Identity, error) {
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
	if mutate && org.Status != types.OrgStatusActive {
		return nil, nil, huma.Error409Conflict("tenant is not active")
	}
	allowed, err := h.authz.Check(ctx, authz.UserObject(id.Subject), relation, authz.OrgObject(org.ID))
	if err != nil {
		return nil, nil, huma.Error503ServiceUnavailable("authorization backend unavailable")
	}
	if !allowed {
		return nil, nil, huma.Error403Forbidden("insufficient permissions: " + relation + " is required")
	}
	return org, id, nil
}

func httpError(err error) error {
	if err == nil {
		return nil
	}
	var targetValidation *resourcetargets.ValidationError
	var targetAuthorization *resourcetargets.AuthorizationError
	switch {
	case errors.Is(err, resourcetargets.ErrTargetDenied):
		return huma.Error403Forbidden("resource target grant required")
	case errors.Is(err, resourcetargets.ErrTargetNotFound), errors.Is(err, catalog.ErrItemNotFound), errors.Is(err, catalog.ErrVersionNotFound), errors.Is(err, ErrPlanNotFound), errors.Is(err, ErrCompanionNotFound):
		return huma.Error404NotFound(err.Error())
	case errors.Is(err, resourcetargets.ErrStaleRevision), errors.Is(err, resourcetargets.ErrUnavailable), errors.Is(err, resourcetargets.ErrConflict), errors.Is(err, ErrPlanConflict), errors.Is(err, scaffold.ErrTemplateDigestMismatch):
		return huma.Error409Conflict(err.Error())
	case errors.Is(err, resourcetargets.ErrInvalidInput), errors.Is(err, ErrInvalidPlanInput), errors.As(err, &targetValidation), errors.Is(err, ErrCapabilityMetadataMissing), errors.Is(err, ErrCapabilityConflict), errors.Is(err, ErrPackRenderContract), errors.Is(err, ErrManagedChartNativeConflict):
		return huma.Error422UnprocessableEntity(err.Error())
	case errors.As(err, &targetAuthorization), artifactadmission.IsTemporary(err):
		return huma.Error503ServiceUnavailable(err.Error())
	default:
		var admissionErr *artifactadmission.Error
		if errors.As(err, &admissionErr) {
			return huma.Error422UnprocessableEntity(err.Error())
		}
		return err
	}
}

type preflightInput struct {
	Org  string `path:"org"`
	Body PlanRequest
}
type preflightOutput struct {
	Body struct {
		Preflight Preflight `json:"preflight"`
	}
}

func (h *Handler) preflight(ctx context.Context, in *preflightInput) (*preflightOutput, error) {
	org, id, err := h.authorize(ctx, in.Org, authz.RelationDeploymentsCreate, true)
	if err != nil {
		return nil, err
	}
	preflight, err := h.svc.Preflight(ctx, in.Body, org.ID, org.Slug, id.Subject)
	if err != nil {
		return nil, httpError(err)
	}
	out := &preflightOutput{}
	out.Body.Preflight = *preflight
	return out, nil
}

type submitInput struct {
	Org  string `path:"org"`
	Body PlanRequest
}
type submitOutput struct {
	Body struct {
		Plan Plan `json:"plan"`
	}
}

func (h *Handler) submit(ctx context.Context, in *submitInput) (*submitOutput, error) {
	org, id, err := h.authorize(ctx, in.Org, authz.RelationDeploymentsCreate, true)
	if err != nil {
		return nil, err
	}
	if in.Body.IdempotencyKey == "" {
		return nil, huma.Error400BadRequest("idempotencyKey is required")
	}
	if h.repoWrite != nil {
		if in.Body.Operation == OperationProvisionExisting {
			err = h.repoWrite.EnforceRecordedRepoWrite(ctx, id, org.ID, in.Body.InstanceID)
		} else {
			err = h.repoWrite.EnforceRepoWrite(ctx, id, org.ID, in.Body.Deployment.RepoID)
		}
		if err != nil {
			return nil, err
		}
	}
	plan, err := h.svc.Submit(ctx, in.Body, org.ID, org.Slug, id.Subject)
	if err != nil {
		return nil, httpError(err)
	}
	out := &submitOutput{}
	out.Body.Plan = *plan
	return out, nil
}

type getPlanInput struct {
	Org string `path:"org"`
	ID  string `path:"id"`
}
type getPlanOutput struct {
	Body struct {
		Plan Plan `json:"plan"`
	}
}

func (h *Handler) get(ctx context.Context, in *getPlanInput) (*getPlanOutput, error) {
	org, id, err := h.authorize(ctx, in.Org, authz.RelationTenantRead, false)
	if err != nil {
		return nil, err
	}
	plan, err := h.svc.Get(ctx, org.ID, in.ID, id.Subject)
	if err != nil {
		return nil, httpError(err)
	}
	out := &getPlanOutput{}
	out.Body.Plan = *plan
	return out, nil
}

type instanceInput struct {
	Org string `path:"org"`
	ID  string `path:"id"`
}
type instanceOutput struct {
	Body struct {
		Observability InstanceObservability `json:"observability"`
	}
}

func (h *Handler) instanceObservability(ctx context.Context, in *instanceInput) (*instanceOutput, error) {
	org, id, err := h.authorize(ctx, in.Org, authz.RelationTenantRead, false)
	if err != nil {
		return nil, err
	}
	status, err := h.svc.InstanceObservability(ctx, org.ID, in.ID, id.Subject)
	if err != nil {
		return nil, httpError(err)
	}
	out := &instanceOutput{}
	out.Body.Observability = *status
	return out, nil
}
