// HTTP handlers for the policy service module (plan §5.11).
package policyservice

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/clusterregistry"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

// TenantResolver resolves a tenant slug to its record (tenancy.Service).
type TenantResolver interface {
	GetTenant(ctx context.Context, slug string) (*types.Organization, error)
}

// Handler exposes the policy service REST surface. The v1 exemption
// approval gate lives here: DecideExemption requires the platform_engineer
// relation; full Approvals-engine integration is a follow-up (§5.11).
type Handler struct {
	svc     *Service
	tenants TenantResolver
	authz   authz.Authorizer
}

func NewHandler(svc *Service, tenants TenantResolver, az authz.Authorizer) *Handler {
	return &Handler{svc: svc, tenants: tenants, authz: az}
}

// RegisterRoutes mounts the policy service API on the huma API instance.
func (h *Handler) RegisterRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "createPolicy",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/policies",
		Summary:     "Create a policy (rego, target request|render)",
		Security:    httpserver.SecurityRequirement(),
	}, h.createPolicy)
	huma.Register(api, huma.Operation{
		OperationID: "listPolicies",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/policies",
		Summary:     "List policies (org + platform-global)",
		Security:    httpserver.SecurityRequirement(),
	}, h.listPolicies)
	huma.Register(api, huma.Operation{
		OperationID: "evaluatePolicies",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/policies/evaluate",
		Summary:     "Dry-run pre-flight policy evaluation",
		Security:    httpserver.SecurityRequirement(),
	}, h.evaluate)
	huma.Register(api, huma.Operation{
		OperationID: "getPolicy",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/policies/{id}",
		Summary:     "Get a policy",
		Security:    httpserver.SecurityRequirement(),
	}, h.getPolicy)
	huma.Register(api, huma.Operation{
		OperationID: "updatePolicy",
		Method:      http.MethodPut,
		Path:        "/api/v1/tenants/{org}/policies/{id}",
		Summary:     "Update a policy (bumps version)",
		Security:    httpserver.SecurityRequirement(),
	}, h.updatePolicy)
	huma.Register(api, huma.Operation{
		OperationID: "deletePolicy",
		Method:      http.MethodDelete,
		Path:        "/api/v1/tenants/{org}/policies/{id}",
		Summary:     "Delete a policy",
		Security:    httpserver.SecurityRequirement(),
	}, h.deletePolicy)

	huma.Register(api, huma.Operation{
		OperationID: "createClusterSet",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/cluster-sets",
		Summary:     "Create a cluster set",
		Security:    httpserver.SecurityRequirement(),
	}, h.createClusterSet)
	huma.Register(api, huma.Operation{
		OperationID: "listClusterSets",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/cluster-sets",
		Summary:     "List cluster sets",
		Security:    httpserver.SecurityRequirement(),
	}, h.listClusterSets)
	huma.Register(api, huma.Operation{
		OperationID: "getClusterSet",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/cluster-sets/{id}",
		Summary:     "Get a cluster set",
		Security:    httpserver.SecurityRequirement(),
	}, h.getClusterSet)
	huma.Register(api, huma.Operation{
		OperationID: "deleteClusterSet",
		Method:      http.MethodDelete,
		Path:        "/api/v1/tenants/{org}/cluster-sets/{id}",
		Summary:     "Delete a cluster set",
		Security:    httpserver.SecurityRequirement(),
	}, h.deleteClusterSet)

	huma.Register(api, huma.Operation{
		OperationID: "createPolicyPack",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/policy-packs",
		Summary:     "Create a policy pack (kyverno|cel-vap)",
		Security:    httpserver.SecurityRequirement(),
	}, h.createPack)
	huma.Register(api, huma.Operation{
		OperationID: "listPolicyPacks",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/policy-packs",
		Summary:     "List policy packs (org + platform-global)",
		Security:    httpserver.SecurityRequirement(),
	}, h.listPacks)
	huma.Register(api, huma.Operation{
		OperationID: "getPolicyPack",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/policy-packs/{id}",
		Summary:     "Get a policy pack",
		Security:    httpserver.SecurityRequirement(),
	}, h.getPack)
	huma.Register(api, huma.Operation{
		OperationID: "assignPolicyPack",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/policy-packs/{id}/assign",
		Summary:     "Assign a policy pack to a clusterset|tenant|cluster",
		Security:    httpserver.SecurityRequirement(),
	}, h.assignPack)
	huma.Register(api, huma.Operation{
		OperationID: "unassignPolicyPack",
		Method:      http.MethodDelete,
		Path:        "/api/v1/tenants/{org}/policy-packs/{id}/assignments/{assignmentId}",
		Summary:     "Remove a policy pack assignment",
		Security:    httpserver.SecurityRequirement(),
	}, h.unassignPack)

	huma.Register(api, huma.Operation{
		OperationID: "requestExemption",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/exemptions",
		Summary:     "Request a time-boxed policy exemption",
		Security:    httpserver.SecurityRequirement(),
	}, h.requestExemption)
	huma.Register(api, huma.Operation{
		OperationID: "listExemptions",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/exemptions",
		Summary:     "List exemptions",
		Security:    httpserver.SecurityRequirement(),
	}, h.listExemptions)
	huma.Register(api, huma.Operation{
		OperationID: "decideExemption",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/exemptions/{id}/decide",
		Summary:     "Approve or reject a pending exemption (platform_engineer only, v1 gate)",
		Security:    httpserver.SecurityRequirement(),
	}, h.decideExemption)
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

func mapErr(err error, notFound error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, notFound):
		return huma.Error404NotFound(notFound.Error())
	case errors.Is(err, ErrAssignmentExists):
		return huma.Error409Conflict(ErrAssignmentExists.Error())
	case errors.Is(err, ErrExemptionNotPending):
		return huma.Error409Conflict(ErrExemptionNotPending.Error())
	case errors.Is(err, ErrInvalidInput):
		return huma.Error422UnprocessableEntity(err.Error())
	}
	return err
}

type createPolicyInput struct {
	Org  string `path:"org"`
	Body struct {
		Name   string `json:"name"`
		Target string `json:"target" doc:"request | render"`
		Engine string `json:"engine" doc:"rego"`
		Source string `json:"source" doc:"Rego source (package inari.policy)"`
	}
}

type policyOutput struct {
	Body struct {
		Policy types.Policy `json:"policy"`
	}
}

func (h *Handler) createPolicy(ctx context.Context, in *createPolicyInput) (*policyOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	p, err := h.svc.CreatePolicy(ctx, id.Subject, org.ID, in.Body.Name, in.Body.Target, in.Body.Engine, in.Body.Source)
	if err != nil {
		return nil, mapErr(err, nil)
	}
	out := &policyOutput{}
	out.Body.Policy = *p
	return out, nil
}

type listPoliciesInput struct {
	Org string `path:"org"`
}

type listPoliciesOutput struct {
	Body struct {
		Policies []types.Policy `json:"policies"`
	}
}

func (h *Handler) listPolicies(ctx context.Context, in *listPoliciesInput) (*listPoliciesOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	policies, err := h.svc.ListPolicies(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	out := &listPoliciesOutput{}
	out.Body.Policies = policies
	return out, nil
}

type policyIDInput struct {
	Org string `path:"org"`
	ID  string `path:"id"`
}

func (h *Handler) getPolicy(ctx context.Context, in *policyIDInput) (*policyOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	p, err := h.svc.GetPolicy(ctx, org.ID, in.ID)
	if err != nil {
		return nil, mapErr(err, ErrPolicyNotFound)
	}
	out := &policyOutput{}
	out.Body.Policy = *p
	return out, nil
}

type updatePolicyInput struct {
	Org  string `path:"org"`
	ID   string `path:"id"`
	Body struct {
		Source  string `json:"source"`
		Enabled bool   `json:"enabled"`
	}
}

func (h *Handler) updatePolicy(ctx context.Context, in *updatePolicyInput) (*policyOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	p, err := h.svc.UpdatePolicy(ctx, id.Subject, org.ID, in.ID, in.Body.Source, in.Body.Enabled)
	if err != nil {
		return nil, mapErr(err, ErrPolicyNotFound)
	}
	out := &policyOutput{}
	out.Body.Policy = *p
	return out, nil
}

func (h *Handler) deletePolicy(ctx context.Context, in *policyIDInput) (*struct{}, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	if err := h.svc.DeletePolicy(ctx, id.Subject, org.ID, in.ID); err != nil {
		return nil, mapErr(err, ErrPolicyNotFound)
	}
	return nil, nil
}

type evaluateInput struct {
	Org  string `path:"org"`
	Body struct {
		ItemID    string          `json:"itemId"`
		Version   string          `json:"version"`
		ClusterID string          `json:"clusterId"`
		Spec      json.RawMessage `json:"spec"`
	}
}

type evaluateOutput struct {
	Body struct {
		Decision types.PolicyDecision `json:"decision"`
	}
}

func (h *Handler) evaluate(ctx context.Context, in *evaluateInput) (*evaluateOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationDeveloper)
	if err != nil {
		return nil, err
	}
	pf := PreFlightInput{
		OrgID: org.ID, ItemID: in.Body.ItemID, Version: in.Body.Version,
		ClusterID: in.Body.ClusterID, Spec: in.Body.Spec, Requester: "user:" + id.Subject,
	}
	if in.Body.ClusterID != "" {
		cluster, err := h.svc.clusters.GetCluster(ctx, in.Body.ClusterID)
		if err != nil {
			if errors.Is(err, clusterregistry.ErrClusterNotFound) {
				return nil, huma.Error404NotFound("cluster not found")
			}
			return nil, mapErr(err, nil)
		}
		if cluster.OrgID != org.ID {
			return nil, huma.Error404NotFound("cluster not found")
		}
		pf.ClusterLabels = cluster.Labels
		pf.ClusterDistribution = cluster.Distribution
	}
	decision, err := h.svc.PreFlight(ctx, pf)
	if err != nil {
		return nil, mapErr(err, nil)
	}
	out := &evaluateOutput{}
	out.Body.Decision = *decision
	return out, nil
}

type createClusterSetInput struct {
	Org  string `path:"org"`
	Body struct {
		Name          string            `json:"name"`
		LabelSelector map[string]string `json:"labelSelector"`
	}
}

type clusterSetOutput struct {
	Body struct {
		ClusterSet types.ClusterSet `json:"clusterSet"`
	}
}

func (h *Handler) createClusterSet(ctx context.Context, in *createClusterSetInput) (*clusterSetOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	cs, err := h.svc.CreateClusterSet(ctx, id.Subject, org.ID, in.Body.Name, in.Body.LabelSelector)
	if err != nil {
		return nil, mapErr(err, nil)
	}
	out := &clusterSetOutput{}
	out.Body.ClusterSet = *cs
	return out, nil
}

type listClusterSetsInput struct {
	Org string `path:"org"`
}

type listClusterSetsOutput struct {
	Body struct {
		ClusterSets []types.ClusterSet `json:"clusterSets"`
	}
}

func (h *Handler) listClusterSets(ctx context.Context, in *listClusterSetsInput) (*listClusterSetsOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	sets, err := h.svc.ListClusterSets(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	out := &listClusterSetsOutput{}
	out.Body.ClusterSets = sets
	return out, nil
}

type clusterSetIDInput struct {
	Org string `path:"org"`
	ID  string `path:"id"`
}

func (h *Handler) getClusterSet(ctx context.Context, in *clusterSetIDInput) (*clusterSetOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	cs, err := h.svc.GetClusterSet(ctx, org.ID, in.ID)
	if err != nil {
		return nil, mapErr(err, ErrClusterSetNotFound)
	}
	out := &clusterSetOutput{}
	out.Body.ClusterSet = *cs
	return out, nil
}

func (h *Handler) deleteClusterSet(ctx context.Context, in *clusterSetIDInput) (*struct{}, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	if err := h.svc.DeleteClusterSet(ctx, id.Subject, org.ID, in.ID); err != nil {
		return nil, mapErr(err, ErrClusterSetNotFound)
	}
	return nil, nil
}

type createPackInput struct {
	Org  string `path:"org"`
	Body struct {
		Name       string          `json:"name"`
		Engine     string          `json:"engine" doc:"kyverno | cel-vap"`
		OCIRef     string          `json:"ociRef,omitempty"`
		Version    string          `json:"version"`
		Parameters json.RawMessage `json:"parameters,omitempty"`
		Manifests  json.RawMessage `json:"manifests"`
	}
}

type packOutput struct {
	Body struct {
		Pack types.PolicyPack `json:"pack"`
	}
}

func (h *Handler) createPack(ctx context.Context, in *createPackInput) (*packOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	p, err := h.svc.CreatePolicyPack(ctx, id.Subject, org.ID, in.Body.Name, in.Body.Engine, in.Body.OCIRef,
		in.Body.Version, in.Body.Parameters, in.Body.Manifests)
	if err != nil {
		return nil, mapErr(err, nil)
	}
	out := &packOutput{}
	out.Body.Pack = *p
	return out, nil
}

type listPacksInput struct {
	Org string `path:"org"`
}

type listPacksOutput struct {
	Body struct {
		Packs []types.PolicyPack `json:"packs"`
	}
}

func (h *Handler) listPacks(ctx context.Context, in *listPacksInput) (*listPacksOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	packs, err := h.svc.ListPolicyPacks(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	out := &listPacksOutput{}
	out.Body.Packs = packs
	return out, nil
}

type packIDInput struct {
	Org string `path:"org"`
	ID  string `path:"id"`
}

func (h *Handler) getPack(ctx context.Context, in *packIDInput) (*packOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	p, err := h.svc.GetPolicyPack(ctx, org.ID, in.ID)
	if err != nil {
		return nil, mapErr(err, ErrPackNotFound)
	}
	out := &packOutput{}
	out.Body.Pack = *p
	return out, nil
}

type assignPackInput struct {
	Org  string `path:"org"`
	ID   string `path:"id"`
	Body struct {
		TargetType string `json:"targetType" doc:"clusterset | tenant | cluster"`
		TargetID   string `json:"targetId"`
	}
}

type assignPackOutput struct {
	Body struct {
		Assignment types.PolicyAssignment `json:"assignment"`
	}
}

func (h *Handler) assignPack(ctx context.Context, in *assignPackInput) (*assignPackOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	a, err := h.svc.Assign(ctx, id.Subject, org.ID, in.ID, in.Body.TargetType, in.Body.TargetID)
	if err != nil {
		return nil, mapErr(err, ErrPackNotFound)
	}
	out := &assignPackOutput{}
	out.Body.Assignment = *a
	return out, nil
}

type unassignPackInput struct {
	Org          string `path:"org"`
	ID           string `path:"id"`
	AssignmentID string `path:"assignmentId"`
}

func (h *Handler) unassignPack(ctx context.Context, in *unassignPackInput) (*struct{}, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	if err := h.svc.Unassign(ctx, id.Subject, org.ID, in.ID, in.AssignmentID); err != nil {
		return nil, mapErr(err, ErrAssignmentNotFound)
	}
	return nil, nil
}

type requestExemptionInput struct {
	Org  string `path:"org"`
	Body struct {
		PolicyID  string          `json:"policyId"`
		Scope     json.RawMessage `json:"scope,omitempty"`
		Reason    string          `json:"reason"`
		ExpiresAt time.Time       `json:"expiresAt"`
	}
}

type exemptionOutput struct {
	Body struct {
		Exemption types.Exemption `json:"exemption"`
	}
}

func (h *Handler) requestExemption(ctx context.Context, in *requestExemptionInput) (*exemptionOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationDeveloper)
	if err != nil {
		return nil, err
	}
	e, err := h.svc.RequestExemption(ctx, id.Subject, org.ID, in.Body.PolicyID, in.Body.Scope, in.Body.Reason, in.Body.ExpiresAt)
	if err != nil {
		return nil, mapErr(err, ErrPolicyNotFound)
	}
	out := &exemptionOutput{}
	out.Body.Exemption = *e
	return out, nil
}

type listExemptionsInput struct {
	Org string `path:"org"`
}

type listExemptionsOutput struct {
	Body struct {
		Exemptions []types.Exemption `json:"exemptions"`
	}
}

func (h *Handler) listExemptions(ctx context.Context, in *listExemptionsInput) (*listExemptionsOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	exemptions, err := h.svc.ListExemptions(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	out := &listExemptionsOutput{}
	out.Body.Exemptions = exemptions
	return out, nil
}

type decideExemptionInput struct {
	Org  string `path:"org"`
	ID   string `path:"id"`
	Body struct {
		Approve bool `json:"approve"`
	}
}

func (h *Handler) decideExemption(ctx context.Context, in *decideExemptionInput) (*exemptionOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	e, err := h.svc.DecideExemption(ctx, id.Subject, org.ID, in.ID, in.Body.Approve)
	if err != nil {
		return nil, mapErr(err, ErrExemptionNotFound)
	}
	out := &exemptionOutput{}
	out.Body.Exemption = *e
	return out, nil
}
