// REST surface for the Scaffolding / Software Templates module (M8, plan
// §3): tenant template browsing and scaffold run lifecycle. Contract
// matches the inari-ui /templates wizard client types.
package scaffold

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

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

// Handler exposes the scaffold REST surface.
type Handler struct {
	svc     *Service
	tenants TenantResolver
	authz   authz.Authorizer
}

// NewHandler builds the module handler.
func NewHandler(svc *Service, tenants TenantResolver, az authz.Authorizer) *Handler {
	return &Handler{svc: svc, tenants: tenants, authz: az}
}

// RegisterRoutes mounts the scaffold API on the huma API instance.
func (h *Handler) RegisterRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "listTemplates",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/templates",
		Summary:     "List software templates visible to the tenant at their effective versions",
		Security:    httpserver.SecurityRequirement(),
	}, h.listTemplates)

	huma.Register(api, huma.Operation{
		OperationID: "getTemplate",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/templates/{name}",
		Summary:     "Get a template with its values schema and optional uiSchema",
		Security:    httpserver.SecurityRequirement(),
	}, h.getTemplate)

	huma.Register(api, huma.Operation{
		OperationID: "createScaffoldRun",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/templates/{name}/runs",
		Summary:     "Create a scaffold run (idempotent: identical resubmits return the existing run)",
		Security:    httpserver.SecurityRequirement(),
	}, h.createRun)

	huma.Register(api, huma.Operation{
		OperationID: "getScaffoldRun",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/scaffold-runs/{runId}",
		Summary:     "Get a scaffold run with per-phase step states and outputs (UI polls this)",
		Security:    httpserver.SecurityRequirement(),
	}, h.getRun)

	huma.Register(api, huma.Operation{
		OperationID: "cancelScaffoldRun",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/scaffold-runs/{runId}/cancel",
		Summary:     "Cooperatively cancel a scaffold run (retains already-created outputs)",
		Security:    httpserver.SecurityRequirement(),
	}, h.cancelRun)
}

// stepView is one step in the UI polling contract (plan §3).
type stepView struct {
	Name     string `json:"name"`
	State    string `json:"state"`
	Attempts int    `json:"attempts"`
	Error    string `json:"error,omitempty"`
}

// runView is the ScaffoldRun JSON shape the UI client consumes (plan §3).
// Internal fields (orgId, templateItemId, idempotencyKey) stay server-side.
type runView struct {
	ID           string          `json:"id"`
	TemplateName string          `json:"templateName"`
	Version      string          `json:"version"`
	DisplayName  string          `json:"displayName"`
	Phase        string          `json:"phase"`
	Steps        []stepView      `json:"steps"`
	Outputs      json.RawMessage `json:"outputs,omitempty"`
	Error        string          `json:"error,omitempty"`
	CreatedBy    string          `json:"createdBy"`
	CreatedAt    time.Time       `json:"createdAt"`
	UpdatedAt    time.Time       `json:"updatedAt"`
}

func (h *Handler) toRunView(ctx context.Context, run *types.ScaffoldRun, steps []types.ScaffoldRunStep) runView {
	v := runView{
		ID: run.ID, TemplateName: h.svc.TemplateNameForRun(ctx, run),
		Version: run.TemplateVersion, DisplayName: run.DisplayName,
		Phase: string(run.Phase), Outputs: run.Outputs, Error: run.Error,
		CreatedBy: run.CreatedBy, CreatedAt: run.CreatedAt, UpdatedAt: run.UpdatedAt,
		Steps: make([]stepView, 0, len(steps)),
	}
	for _, st := range steps {
		v.Steps = append(v.Steps, stepView{Name: st.Name, State: st.State, Attempts: st.Attempts, Error: st.Error})
	}
	return v
}

type listTemplatesInput struct {
	Org string `path:"org"`
}

type listTemplatesOutput struct {
	Body struct {
		Templates []TemplateSummary `json:"templates"`
	}
}

func (h *Handler) listTemplates(ctx context.Context, in *listTemplatesInput) (*listTemplatesOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	templates, err := h.svc.ListTemplates(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	out := &listTemplatesOutput{}
	out.Body.Templates = templates
	return out, nil
}

type templatePathInput struct {
	Org  string `path:"org"`
	Name string `path:"name"`
}

type getTemplateOutput struct {
	Body struct {
		Template TemplateDetail `json:"template"`
	}
}

func (h *Handler) getTemplate(ctx context.Context, in *templatePathInput) (*getTemplateOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	tpl, err := h.svc.GetTemplate(ctx, org.ID, in.Name)
	if errors.Is(err, ErrTemplateNotFound) {
		return nil, huma.Error404NotFound("template not found")
	}
	if err != nil {
		return nil, err
	}
	out := &getTemplateOutput{}
	out.Body.Template = *tpl
	return out, nil
}

type createRunInput struct {
	Org  string `path:"org"`
	Name string `path:"name"`
	Body struct {
		Version     string         `json:"version,omitempty" doc:"Template version; defaults to the tenant's effective version"`
		DisplayName string         `json:"displayName,omitempty"`
		Values      map[string]any `json:"values"`
	}
}

type createRunOutput struct {
	Status int
	Body   struct {
		Run runView `json:"run"`
	}
}

func (h *Handler) createRun(ctx context.Context, in *createRunInput) (*createRunOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationDeveloper)
	if err != nil {
		return nil, err
	}
	values, err := json.Marshal(in.Body.Values)
	if err != nil {
		return nil, huma.Error400BadRequest("values must be a JSON object")
	}
	run, steps, existed, err := h.svc.CreateRun(ctx, id.Subject, org.ID, in.Name, in.Body.Version, in.Body.DisplayName, values)
	var valErr *ValidationError
	switch {
	case errors.As(err, &valErr):
		errs := make([]error, 0, len(valErr.Fields))
		for _, f := range valErr.Fields {
			errs = append(errs, fmt.Errorf("%s: %s", f.Path, f.Message))
		}
		return nil, huma.Error422UnprocessableEntity("values failed template schema validation", errs...)
	case errors.Is(err, ErrTemplateNotFound):
		return nil, huma.Error404NotFound("template not found")
	case errors.Is(err, ErrVersionNotFound):
		return nil, huma.Error400BadRequest("unknown template version")
	case err != nil:
		return nil, err
	}
	out := &createRunOutput{Status: http.StatusCreated}
	if existed {
		out.Status = http.StatusOK
	}
	out.Body.Run = h.toRunView(ctx, run, steps)
	return out, nil
}

type runPathInput struct {
	Org   string `path:"org"`
	RunID string `path:"runId"`
}

type getRunOutput struct {
	Body struct {
		Run runView `json:"run"`
	}
}

func (h *Handler) getRun(ctx context.Context, in *runPathInput) (*getRunOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	run, steps, err := h.svc.GetRun(ctx, org.ID, in.RunID)
	if errors.Is(err, ErrRunNotFound) {
		return nil, huma.Error404NotFound("scaffold run not found")
	}
	if err != nil {
		return nil, err
	}
	out := &getRunOutput{}
	out.Body.Run = h.toRunView(ctx, run, steps)
	return out, nil
}

func (h *Handler) cancelRun(ctx context.Context, in *runPathInput) (*struct{}, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationDeveloper)
	if err != nil {
		return nil, err
	}
	err = h.svc.CancelRun(ctx, id.Subject, org.ID, in.RunID)
	if errors.Is(err, ErrRunNotFound) {
		return nil, huma.Error404NotFound("scaffold run not found")
	}
	if errors.Is(err, ErrInvalidState) {
		return nil, huma.Error409Conflict("run is already terminal")
	}
	return nil, err
}

// authorizeOrg performs coarse PEP (org claim) + fine PEP (OpenFGA Check).
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
