package verification

import (
	"context"
	"errors"
	"net/http"
	"strings"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/artifactadmission"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/resourcetargets"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
	"github.com/danielgtaylor/huma/v2"
)

// TenantResolver resolves a tenant slug to its stable org ID.
type TenantResolver interface {
	GetTenant(ctx context.Context, slug string) (*types.Organization, error)
}

// Handler exposes platform and team verification APIs. No result-ingest route
// exists; reports arrive only on the authenticated agent stream.
type Handler struct {
	svc     *Service
	tenants TenantResolver
	authz   authz.Authorizer
}

func NewHandler(svc *Service, tenants TenantResolver, az authz.Authorizer) *Handler {
	return &Handler{svc: svc, tenants: tenants, authz: az}
}

func registerRoute[I, O any](api huma.API, operation huma.Operation, handler func(context.Context, *I) (*O, error)) {
	operation.Security = httpserver.SecurityRequirement()
	huma.Register(api, operation, handler)
}

func (h *Handler) RegisterRoutes(api huma.API) {
	registerRoute(api, huma.Operation{OperationID: "previewVerificationSuite", Method: http.MethodPost, Path: "/api/v1/tenants/{org}/verification-suites/preview", Summary: "Cryptographically preview a platform suite release"}, h.previewSuite)
	registerRoute(api, huma.Operation{OperationID: "createVerificationSuite", Method: http.MethodPost, Path: "/api/v1/tenants/{org}/verification-suites", Summary: "Import an exact verified suite release"}, h.createSuite)
	registerRoute(api, huma.Operation{OperationID: "listVerificationSuites", Method: http.MethodGet, Path: "/api/v1/tenants/{org}/verification-suites", Summary: "List admitted suite releases"}, h.listSuites)
	registerRoute(api, huma.Operation{OperationID: "getVerificationEnvironment", Method: http.MethodGet, Path: "/api/v1/tenants/{org}/verification-environments/{targetId}", Summary: "Get target verification environment policy"}, h.getEnvironment)
	registerRoute(api, huma.Operation{OperationID: "putVerificationEnvironment", Method: http.MethodPut, Path: "/api/v1/tenants/{org}/verification-environments/{targetId}", Summary: "Set target verification environment policy"}, h.putEnvironment)
	registerRoute(api, huma.Operation{OperationID: "previewVerificationGrant", Method: http.MethodPost, Path: "/api/v1/tenants/{org}/verification-environments/{id}/grants/preview", Summary: "Preview exact suite digest and profile grant"}, h.previewGrant)
	registerRoute(api, huma.Operation{OperationID: "createVerificationGrant", Method: http.MethodPost, Path: "/api/v1/tenants/{org}/verification-environments/{id}/grants", Summary: "Create or revise exact suite grant"}, h.createGrant)
	registerRoute(api, huma.Operation{OperationID: "revokeVerificationGrant", Method: http.MethodDelete, Path: "/api/v1/tenants/{org}/verification-grants/{id}", Summary: "Revoke new runs and evidence for a suite grant"}, h.revokeGrant)
	registerRoute(api, huma.Operation{OperationID: "getInstanceVerification", Method: http.MethodGet, Path: "/api/v1/tenants/{org}/instances/{id}/verification", Summary: "Get instance verification policy and status"}, h.getVerification)
	registerRoute(api, huma.Operation{OperationID: "previewInstanceVerification", Method: http.MethodPost, Path: "/api/v1/tenants/{org}/instances/{id}/verification/preview", Summary: "Preview effective verification policy without side effects"}, h.previewPolicy)
	registerRoute(api, huma.Operation{OperationID: "putInstanceVerification", Method: http.MethodPut, Path: "/api/v1/tenants/{org}/instances/{id}/verification", Summary: "Save a verified team policy revision"}, h.putPolicy)
	registerRoute(api, huma.Operation{OperationID: "disableInstanceVerification", Method: http.MethodDelete, Path: "/api/v1/tenants/{org}/instances/{id}/verification", Summary: "Disable future verification triggers"}, h.disablePolicy)
	registerRoute(api, huma.Operation{OperationID: "createInstanceVerificationRun", Method: http.MethodPost, Path: "/api/v1/tenants/{org}/instances/{id}/verification/runs", Summary: "Dry-run or request an exact manual verification run"}, h.createRun)
	registerRoute(api, huma.Operation{OperationID: "listInstanceVerificationRuns", Method: http.MethodGet, Path: "/api/v1/tenants/{org}/instances/{id}/verification/runs", Summary: "List verification run history"}, h.listRuns)
	registerRoute(api, huma.Operation{OperationID: "getInstanceVerificationRun", Method: http.MethodGet, Path: "/api/v1/tenants/{org}/instances/{id}/verification/runs/{runId}", Summary: "Get verification run details"}, h.getRun)
	registerRoute(api, huma.Operation{OperationID: "retryInstanceVerificationRun", Method: http.MethodPost, Path: "/api/v1/tenants/{org}/instances/{id}/verification/runs/{runId}/retry", Summary: "Retry a failed verification attempt after revalidation"}, h.retryRun)
}

func (h *Handler) authorize(ctx context.Context, slug, relation string, manage bool) (*types.Organization, *authn.Identity, error) {
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
	if manage && org.Status != types.OrgStatusActive {
		return nil, nil, huma.Error409Conflict("tenant is being deleted and no longer accepts changes")
	}
	if relation != "" {
		allowed, err := h.authz.Check(ctx, authz.UserObject(id.Subject), relation, authz.OrgObject(org.ID))
		if err != nil {
			return nil, nil, huma.Error503ServiceUnavailable("authorization backend unavailable")
		}
		if !allowed {
			return nil, nil, huma.Error403Forbidden("insufficient permissions")
		}
	}
	return org, id, nil
}

func (h *Handler) authorizeSuite(ctx context.Context, slug string, manage bool) (*types.Organization, *authn.Identity, error) {
	org, id, err := h.authorize(ctx, slug, authz.RelationResourceTargetsManage, manage)
	if err != nil {
		return nil, nil, err
	}
	allowed, err := h.authz.Check(ctx, authz.UserObject(id.Subject), authz.RelationCatalogManage, authz.OrgObject(org.ID))
	if err != nil {
		return nil, nil, huma.Error503ServiceUnavailable("authorization backend unavailable")
	}
	if !allowed {
		return nil, nil, huma.Error403Forbidden("catalog.manage and resourcetargets.manage are required")
	}
	return org, id, nil
}

func verificationHTTPError(err error) error {
	if err == nil {
		return nil
	}
	var admission *artifactadmission.Error
	var eligibility *trustedsource.EligibilityError
	switch {
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrRunNotFound), errors.Is(err, inventory.ErrInstanceNotFound), errors.Is(err, resourcetargets.ErrTargetNotFound):
		return huma.Error404NotFound("verification object not found")
	case errors.Is(err, resourcetargets.ErrTargetDenied):
		return huma.Error403Forbidden("deployment target use grant required")
	case errors.Is(err, ErrConflict), errors.Is(err, ErrConcurrency), errors.Is(err, ErrExternalGateClosed), errors.Is(err, resourcetargets.ErrStaleRevision), errors.Is(err, resourcetargets.ErrConflict):
		return huma.Error409Conflict(err.Error())
	case errors.As(err, &eligibility):
		return huma.Error422UnprocessableEntity(err.Error())
	case errors.As(err, &admission):
		if admission.Temporary || admission.Code == artifactadmission.CodeUnavailable {
			return huma.Error503ServiceUnavailable("artifact admission unavailable")
		}
		return huma.Error422UnprocessableEntity(err.Error())
	default:
		message := err.Error()
		for _, prefix := range []string{"suite_", "verification_", "target_stale", "app_", "side_effect", "rbac_", "test_evidence", "profile", "policy", "timeout", "concurrency", "retention", "grant", "manual trigger", "idempotencyKey", "only a terminal"} {
			if strings.HasPrefix(message, prefix) {
				return huma.Error422UnprocessableEntity(message)
			}
		}
		return err
	}
}

type suiteInput struct {
	Org  string `path:"org"`
	Body SuiteAdmissionInput
}
type suiteOutput struct{ Body SuitePreview }
type suiteListOutput struct {
	Body struct {
		Suites []SuiteRelease `json:"suites"`
	}
}

func (h *Handler) previewSuite(ctx context.Context, in *suiteInput) (*suiteOutput, error) {
	org, _, err := h.authorizeSuite(ctx, in.Org, false)
	if err != nil {
		return nil, err
	}
	in.Body.OrgID = org.ID
	preview, err := h.svc.PreviewSuite(ctx, in.Body)
	if err != nil {
		return nil, verificationHTTPError(err)
	}
	return &suiteOutput{Body: *preview}, nil
}

func (h *Handler) createSuite(ctx context.Context, in *suiteInput) (*suiteOutput, error) {
	org, id, err := h.authorizeSuite(ctx, in.Org, true)
	if err != nil {
		return nil, err
	}
	in.Body.OrgID = org.ID
	release, err := h.svc.CreateSuiteRelease(ctx, "user:"+id.Subject, in.Body)
	if err != nil {
		return nil, verificationHTTPError(err)
	}
	return &suiteOutput{Body: SuitePreview{Release: release, Gate: h.svc.GateStatus(), SideEffectsPerformed: 0}}, nil
}

func (h *Handler) listSuites(ctx context.Context, in *orgPathInput) (*suiteListOutput, error) {
	org, _, err := h.authorize(ctx, in.Org, authz.RelationTenantRead, false)
	if err != nil {
		return nil, err
	}
	suites, err := h.svc.ListSuiteReleases(ctx, org.ID)
	out := &suiteListOutput{}
	out.Body.Suites = suites
	return out, verificationHTTPError(err)
}

type orgPathInput struct {
	Org string `path:"org"`
}
type environmentInput struct {
	Org      string `path:"org"`
	TargetID string `path:"targetId"`
	Body     EnvironmentPolicy
}
type environmentGetInput struct {
	Org      string `path:"org"`
	TargetID string `path:"targetId"`
}
type environmentOutput struct{ Body EnvironmentPolicy }

func (h *Handler) getEnvironment(ctx context.Context, in *environmentGetInput) (*environmentOutput, error) {
	org, _, err := h.authorize(ctx, in.Org, authz.RelationTenantRead, false)
	if err != nil {
		return nil, err
	}
	policy, err := h.svc.GetEnvironmentPolicy(ctx, org.ID, in.TargetID)
	if err != nil {
		return nil, verificationHTTPError(err)
	}
	return &environmentOutput{Body: *policy}, nil
}

func (h *Handler) putEnvironment(ctx context.Context, in *environmentInput) (*environmentOutput, error) {
	org, id, err := h.authorize(ctx, in.Org, authz.RelationResourceTargetsManage, true)
	if err != nil {
		return nil, err
	}
	in.Body.OrgID, in.Body.TargetID = org.ID, in.TargetID
	policy, err := h.svc.PutEnvironmentPolicy(ctx, "user:"+id.Subject, &in.Body)
	if err != nil {
		return nil, verificationHTTPError(err)
	}
	return &environmentOutput{Body: *policy}, nil
}

type grantInput struct {
	Org  string `path:"org"`
	ID   string `path:"id"`
	Body SuiteGrant
}
type grantOutput struct{ Body SuitePreview }
type grantCreateOutput struct{ Body SuiteGrant }

func (h *Handler) previewGrant(ctx context.Context, in *grantInput) (*grantOutput, error) {
	org, _, err := h.authorize(ctx, in.Org, authz.RelationResourceTargetsManage, false)
	if err != nil {
		return nil, err
	}
	in.Body.OrgID, in.Body.EnvironmentPolicyID = org.ID, in.ID
	preview, err := h.svc.PreviewGrant(ctx, org.ID, in.ID, &in.Body)
	if err != nil {
		return nil, verificationHTTPError(err)
	}
	return &grantOutput{Body: *preview}, nil
}

func (h *Handler) createGrant(ctx context.Context, in *grantInput) (*grantCreateOutput, error) {
	org, id, err := h.authorize(ctx, in.Org, authz.RelationResourceTargetsManage, true)
	if err != nil {
		return nil, err
	}
	in.Body.OrgID, in.Body.EnvironmentPolicyID = org.ID, in.ID
	grant, err := h.svc.PutGrant(ctx, "user:"+id.Subject, &in.Body)
	if err != nil {
		return nil, verificationHTTPError(err)
	}
	return &grantCreateOutput{Body: *grant}, nil
}

type grantRevokeInput struct {
	Org string `path:"org"`
	ID  string `path:"id"`
}
type statusOutput struct {
	Body struct {
		Status string `json:"status"`
	}
}

func (h *Handler) revokeGrant(ctx context.Context, in *grantRevokeInput) (*statusOutput, error) {
	org, id, err := h.authorize(ctx, in.Org, authz.RelationResourceTargetsManage, true)
	if err != nil {
		return nil, err
	}
	if err := h.svc.RevokeGrant(ctx, org.ID, "user:"+id.Subject, in.ID); err != nil {
		return nil, verificationHTTPError(err)
	}
	out := &statusOutput{}
	out.Body.Status = "revoked"
	return out, nil
}

type policyInput struct {
	Org  string `path:"org"`
	ID   string `path:"id"`
	Body VerificationPolicy
}
type policyOutput struct{ Body PolicyPreview }
type policyCreateOutput struct{ Body VerificationPolicy }

func (h *Handler) previewPolicy(ctx context.Context, in *policyInput) (*policyOutput, error) {
	org, id, err := h.authorize(ctx, in.Org, authz.RelationDeploymentsCreate, true)
	if err != nil {
		return nil, err
	}
	in.Body.OrgID, in.Body.InstanceID = org.ID, in.ID
	preview, err := h.svc.PreviewPolicy(ctx, org.ID, "user:"+id.Subject, &in.Body)
	if err != nil {
		return nil, verificationHTTPError(err)
	}
	return &policyOutput{Body: *preview}, nil
}

func (h *Handler) putPolicy(ctx context.Context, in *policyInput) (*policyCreateOutput, error) {
	org, id, err := h.authorize(ctx, in.Org, authz.RelationDeploymentsCreate, true)
	if err != nil {
		return nil, err
	}
	in.Body.OrgID, in.Body.InstanceID = org.ID, in.ID
	policy, err := h.svc.PutPolicy(ctx, org.ID, "user:"+id.Subject, &in.Body)
	if err != nil {
		return nil, verificationHTTPError(err)
	}
	return &policyCreateOutput{Body: *policy}, nil
}

type instanceInput struct {
	Org string `path:"org"`
	ID  string `path:"id"`
}
type verificationOutput struct{ Body VerificationView }

func (h *Handler) getVerification(ctx context.Context, in *instanceInput) (*verificationOutput, error) {
	org, _, err := h.authorize(ctx, in.Org, authz.RelationTenantRead, false)
	if err != nil {
		return nil, err
	}
	view, err := h.svc.GetVerification(ctx, org.ID, in.ID)
	if err != nil {
		return nil, verificationHTTPError(err)
	}
	return &verificationOutput{Body: *view}, nil
}

func (h *Handler) disablePolicy(ctx context.Context, in *instanceInput) (*policyCreateOutput, error) {
	org, id, err := h.authorize(ctx, in.Org, authz.RelationDeploymentsCreate, true)
	if err != nil {
		return nil, err
	}
	policy, err := h.svc.DisablePolicy(ctx, org.ID, "user:"+id.Subject, in.ID)
	if err != nil {
		return nil, verificationHTTPError(err)
	}
	return &policyCreateOutput{Body: *policy}, nil
}

type runInput struct {
	Org  string `path:"org"`
	ID   string `path:"id"`
	Body struct {
		IdempotencyKey string `json:"idempotencyKey"`
		DryRun         bool   `json:"dryRun,omitempty"`
	}
}
type runOutput struct {
	Body struct {
		Run     *Run           `json:"run,omitempty"`
		Preview *PolicyPreview `json:"preview,omitempty"`
	}
}

func (h *Handler) createRun(ctx context.Context, in *runInput) (*runOutput, error) {
	org, id, err := h.authorize(ctx, in.Org, authz.RelationDeploymentsCreate, true)
	if err != nil {
		return nil, err
	}
	out := &runOutput{}
	if in.Body.DryRun {
		policy, err := h.svc.store.GetCurrentPolicy(ctx, h.svc.db.Pool, org.ID, in.ID)
		if err != nil {
			return nil, verificationHTTPError(err)
		}
		preview, err := h.svc.PreviewPolicy(ctx, org.ID, "user:"+id.Subject, policy)
		out.Body.Preview = preview
		return out, verificationHTTPError(err)
	}
	run, err := h.svc.CreateManualRun(ctx, org.ID, "user:"+id.Subject, in.ID, in.Body.IdempotencyKey)
	out.Body.Run = run
	return out, verificationHTTPError(err)
}

type runListInput struct {
	Org   string `path:"org"`
	ID    string `path:"id"`
	Limit int    `query:"limit" minimum:"1" maximum:"200" default:"50"`
}
type runListOutput struct {
	Body struct {
		Runs []Run `json:"runs"`
	}
}

func (h *Handler) listRuns(ctx context.Context, in *runListInput) (*runListOutput, error) {
	org, _, err := h.authorize(ctx, in.Org, authz.RelationTenantRead, false)
	if err != nil {
		return nil, err
	}
	runs, err := h.svc.ListRuns(ctx, org.ID, in.ID, in.Limit)
	out := &runListOutput{}
	out.Body.Runs = runs
	return out, verificationHTTPError(err)
}

type runGetInput struct {
	Org   string `path:"org"`
	ID    string `path:"id"`
	RunID string `path:"runId"`
}
type runDetailOutput struct{ Body Run }

func (h *Handler) getRun(ctx context.Context, in *runGetInput) (*runDetailOutput, error) {
	org, _, err := h.authorize(ctx, in.Org, authz.RelationTenantRead, false)
	if err != nil {
		return nil, err
	}
	run, err := h.svc.GetRun(ctx, org.ID, in.ID, in.RunID)
	if err != nil {
		return nil, verificationHTTPError(err)
	}
	return &runDetailOutput{Body: *run}, nil
}

func (h *Handler) retryRun(ctx context.Context, in *runGetInput) (*runDetailOutput, error) {
	org, id, err := h.authorize(ctx, in.Org, authz.RelationDeploymentsCreate, true)
	if err != nil {
		return nil, err
	}
	run, err := h.svc.RetryRun(ctx, org.ID, "user:"+id.Subject, in.ID, in.RunID)
	if err != nil {
		return nil, verificationHTTPError(err)
	}
	return &runDetailOutput{Body: *run}, nil
}
