// HTTP handlers for the fleet manager module (plan §5.11): ClusterSets,
// rollouts (incl. stop/resume/rollback), agent channels, drift events, and
// bulk operations.
package fleetmanager

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

// Handler exposes the fleet manager REST surface.
type Handler struct {
	svc     *Service
	tenants TenantResolver
	authz   authz.Authorizer
}

func NewHandler(svc *Service, tenants TenantResolver, az authz.Authorizer) *Handler {
	return &Handler{svc: svc, tenants: tenants, authz: az}
}

// RegisterRoutes mounts the fleet manager API on the huma API instance.
func (h *Handler) RegisterRoutes(api huma.API) {
	op := func(id, method, path, summary string) huma.Operation {
		return huma.Operation{OperationID: id, Method: method, Path: path, Summary: summary, Security: httpserver.SecurityRequirement()}
	}
	huma.Register(api, op("createClusterSet", http.MethodPost, "/api/v1/tenants/{org}/cluster-sets", "Create a cluster set"), h.createClusterSet)
	huma.Register(api, op("listClusterSets", http.MethodGet, "/api/v1/tenants/{org}/cluster-sets", "List cluster sets"), h.listClusterSets)
	huma.Register(api, op("getClusterSet", http.MethodGet, "/api/v1/tenants/{org}/cluster-sets/{id}", "Get a cluster set"), h.getClusterSet)
	huma.Register(api, op("deleteClusterSet", http.MethodDelete, "/api/v1/tenants/{org}/cluster-sets/{id}", "Delete a cluster set"), h.deleteClusterSet)
	huma.Register(api, op("listClusterSetMembers", http.MethodGet, "/api/v1/tenants/{org}/cluster-sets/{id}/members", "Resolve cluster set members"), h.clusterSetMembers)

	huma.Register(api, op("createRollout", http.MethodPost, "/api/v1/tenants/{org}/rollouts", "Create a staged fleet rollout"), h.createRollout)
	huma.Register(api, op("listRollouts", http.MethodGet, "/api/v1/tenants/{org}/rollouts", "List rollouts"), h.listRollouts)
	huma.Register(api, op("getRollout", http.MethodGet, "/api/v1/tenants/{org}/rollouts/{id}", "Get a rollout"), h.getRollout)
	huma.Register(api, op("startRollout", http.MethodPost, "/api/v1/tenants/{org}/rollouts/{id}/start", "Start a rollout"), h.startRollout)
	huma.Register(api, op("stopRollout", http.MethodPost, "/api/v1/tenants/{org}/rollouts/{id}/stop", "Stop (pause) a rollout"), h.stopRollout)
	huma.Register(api, op("resumeRollout", http.MethodPost, "/api/v1/tenants/{org}/rollouts/{id}/resume", "Resume a paused rollout"), h.resumeRollout)
	huma.Register(api, op("rollbackRollout", http.MethodPost, "/api/v1/tenants/{org}/rollouts/{id}/rollback", "Roll back to a previous version"), h.rollbackRollout)
	huma.Register(api, op("listRolloutTargets", http.MethodGet, "/api/v1/tenants/{org}/rollouts/{id}/targets", "List rollout target status for a stage"), h.rolloutTargets)

	huma.Register(api, op("setAgentChannel", http.MethodPut, "/api/v1/tenants/{org}/cluster-sets/{id}/channels/{channel}", "Pin desired agent version for a channel"), h.setAgentChannel)
	huma.Register(api, op("listAgentChannels", http.MethodGet, "/api/v1/tenants/{org}/agent-channels", "List agent channel pins"), h.listAgentChannels)

	huma.Register(api, op("listDrift", http.MethodGet, "/api/v1/tenants/{org}/drift", "List drift events"), h.listDrift)

	huma.Register(api, op("bulkQueryClusters", http.MethodPost, "/api/v1/tenants/{org}/bulk/clusters:query", "Label query across the fleet"), h.bulkQueryClusters)
	huma.Register(api, op("bulkDecideApprovals", http.MethodPost, "/api/v1/tenants/{org}/bulk/approvals:decide", "Bulk approve/reject approvals"), h.bulkDecideApprovals)
	huma.Register(api, op("bulkAssignPolicy", http.MethodPost, "/api/v1/tenants/{org}/bulk/policy:assign", "Bulk assign a policy pack to cluster sets"), h.bulkAssignPolicy)
	huma.Register(api, op("bulkPinCatalog", http.MethodPost, "/api/v1/tenants/{org}/bulk/catalog:pin", "Bulk pin catalog items to a version"), h.bulkPinCatalog)
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

func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrNotFound):
		return huma.Error404NotFound(ErrNotFound.Error())
	case errors.Is(err, ErrInvalidInput):
		return huma.Error422UnprocessableEntity(err.Error())
	case errors.Is(err, ErrInvalidTransition):
		return huma.Error409Conflict(err.Error())
	}
	return err
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
		return nil, mapErr(err)
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
		return nil, mapErr(err)
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
		return nil, mapErr(err)
	}
	return nil, nil
}

type membersOutput struct {
	Body struct {
		Clusters []types.Cluster `json:"clusters"`
	}
}

func (h *Handler) clusterSetMembers(ctx context.Context, in *clusterSetIDInput) (*membersOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	members, err := h.svc.ClusterSetMembers(ctx, org.ID, in.ID)
	if err != nil {
		return nil, mapErr(err)
	}
	out := &membersOutput{}
	out.Body.Clusters = members
	return out, nil
}

type createRolloutInput struct {
	Org  string `path:"org"`
	Body struct {
		Name           string               `json:"name"`
		Kind           string               `json:"kind" doc:"capability | policy_pack | agent_upgrade | catalog_version"`
		TargetRef      string               `json:"targetRef"`
		DesiredVersion string               `json:"desiredVersion"`
		Stages         []types.RolloutStage `json:"stages"`
	}
}

type rolloutOutput struct {
	Body struct {
		Rollout types.Rollout `json:"rollout"`
	}
}

func (h *Handler) createRollout(ctx context.Context, in *createRolloutInput) (*rolloutOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.CreateRollout(ctx, id.Subject, org.ID, CreateRolloutInput{
		Name: in.Body.Name, Kind: in.Body.Kind, TargetRef: in.Body.TargetRef,
		DesiredVersion: in.Body.DesiredVersion, Stages: in.Body.Stages,
	})
	if err != nil {
		return nil, mapErr(err)
	}
	out := &rolloutOutput{}
	out.Body.Rollout = *r
	return out, nil
}

type listRolloutsInput struct {
	Org string `path:"org"`
}

type listRolloutsOutput struct {
	Body struct {
		Rollouts []types.Rollout `json:"rollouts"`
	}
}

func (h *Handler) listRollouts(ctx context.Context, in *listRolloutsInput) (*listRolloutsOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	rs, err := h.svc.ListRollouts(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	out := &listRolloutsOutput{}
	out.Body.Rollouts = rs
	return out, nil
}

type rolloutIDInput struct {
	Org string `path:"org"`
	ID  string `path:"id"`
}

func (h *Handler) getRollout(ctx context.Context, in *rolloutIDInput) (*rolloutOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.GetRollout(ctx, org.ID, in.ID)
	if err != nil {
		return nil, mapErr(err)
	}
	out := &rolloutOutput{}
	out.Body.Rollout = *r
	return out, nil
}

func (h *Handler) startRollout(ctx context.Context, in *rolloutIDInput) (*rolloutOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.StartRollout(ctx, id.Subject, org.ID, in.ID)
	if err != nil {
		return nil, mapErr(err)
	}
	out := &rolloutOutput{}
	out.Body.Rollout = *r
	return out, nil
}

func (h *Handler) stopRollout(ctx context.Context, in *rolloutIDInput) (*rolloutOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.StopRollout(ctx, id.Subject, org.ID, in.ID)
	if err != nil {
		return nil, mapErr(err)
	}
	out := &rolloutOutput{}
	out.Body.Rollout = *r
	return out, nil
}

func (h *Handler) resumeRollout(ctx context.Context, in *rolloutIDInput) (*rolloutOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.ResumeRollout(ctx, id.Subject, org.ID, in.ID)
	if err != nil {
		return nil, mapErr(err)
	}
	out := &rolloutOutput{}
	out.Body.Rollout = *r
	return out, nil
}

type rollbackInput struct {
	Org  string `path:"org"`
	ID   string `path:"id"`
	Body struct {
		ToVersion string `json:"toVersion"`
	}
}

func (h *Handler) rollbackRollout(ctx context.Context, in *rollbackInput) (*rolloutOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.Rollback(ctx, id.Subject, org.ID, in.ID, in.Body.ToVersion)
	if err != nil {
		return nil, mapErr(err)
	}
	out := &rolloutOutput{}
	out.Body.Rollout = *r
	return out, nil
}

type targetsInput struct {
	Org   string `path:"org"`
	ID    string `path:"id"`
	Stage int    `query:"stage"`
}

type targetsOutput struct {
	Body struct {
		Targets []types.RolloutTarget `json:"targets"`
	}
}

func (h *Handler) rolloutTargets(ctx context.Context, in *targetsInput) (*targetsOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	targets, err := h.svc.RolloutTargets(ctx, org.ID, in.ID, in.Stage)
	if err != nil {
		return nil, mapErr(err)
	}
	out := &targetsOutput{}
	out.Body.Targets = targets
	return out, nil
}

type setChannelInput struct {
	Org     string `path:"org"`
	ID      string `path:"id"`
	Channel string `path:"channel"`
	Body    struct {
		DesiredAgentVersion string `json:"desiredAgentVersion"`
	}
}

type channelOutput struct {
	Body struct {
		Channel types.AgentChannel `json:"channel"`
	}
}

func (h *Handler) setAgentChannel(ctx context.Context, in *setChannelInput) (*channelOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	c, err := h.svc.SetAgentChannel(ctx, id.Subject, org.ID, in.ID, in.Channel, in.Body.DesiredAgentVersion)
	if err != nil {
		return nil, mapErr(err)
	}
	out := &channelOutput{}
	out.Body.Channel = *c
	return out, nil
}

type listChannelsInput struct {
	Org string `path:"org"`
}

type listChannelsOutput struct {
	Body struct {
		Channels []types.AgentChannel `json:"channels"`
	}
}

func (h *Handler) listAgentChannels(ctx context.Context, in *listChannelsInput) (*listChannelsOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	cs, err := h.svc.ListAgentChannels(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	out := &listChannelsOutput{}
	out.Body.Channels = cs
	return out, nil
}

type listDriftInput struct {
	Org       string `path:"org"`
	ClusterID string `query:"clusterId"`
	Status    string `query:"status"`
}

type listDriftOutput struct {
	Body struct {
		DriftEvents []types.DriftEvent `json:"driftEvents"`
	}
}

func (h *Handler) listDrift(ctx context.Context, in *listDriftInput) (*listDriftOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	ds, err := h.svc.ListDrift(ctx, org.ID, in.ClusterID, in.Status)
	if err != nil {
		return nil, err
	}
	out := &listDriftOutput{}
	out.Body.DriftEvents = ds
	return out, nil
}

type bulkQueryInput struct {
	Org  string `path:"org"`
	Body struct {
		LabelSelector map[string]string `json:"labelSelector"`
	}
}

func (h *Handler) bulkQueryClusters(ctx context.Context, in *bulkQueryInput) (*membersOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	clusters, err := h.svc.QueryClusters(ctx, org.ID, in.Body.LabelSelector)
	if err != nil {
		return nil, mapErr(err)
	}
	out := &membersOutput{}
	out.Body.Clusters = clusters
	return out, nil
}

type bulkDecideInput struct {
	Org  string `path:"org"`
	Body struct {
		ApprovalIDs []string `json:"approvalIds"`
		Approve     bool     `json:"approve"`
		Reason      string   `json:"reason,omitempty"`
	}
}

type bulkResultsOutput struct {
	Body struct {
		Results []BulkItemResult `json:"results"`
	}
}

func (h *Handler) bulkDecideApprovals(ctx context.Context, in *bulkDecideInput) (*bulkResultsOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	res, err := h.svc.BulkDecideApprovals(ctx, org.ID, id.Subject, in.Body.ApprovalIDs, in.Body.Approve, in.Body.Reason)
	if err != nil {
		return nil, mapErr(err)
	}
	out := &bulkResultsOutput{}
	out.Body.Results = res
	return out, nil
}

type bulkAssignPolicyInput struct {
	Org  string `path:"org"`
	Body struct {
		PackID        string   `json:"packId"`
		ClusterSetIDs []string `json:"clusterSetIds"`
	}
}

func (h *Handler) bulkAssignPolicy(ctx context.Context, in *bulkAssignPolicyInput) (*bulkResultsOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	res, err := h.svc.BulkAssignPolicy(ctx, id.Subject, org.ID, in.Body.PackID, in.Body.ClusterSetIDs)
	if err != nil {
		return nil, mapErr(err)
	}
	out := &bulkResultsOutput{}
	out.Body.Results = res
	return out, nil
}

type bulkPinCatalogInput struct {
	Org  string `path:"org"`
	Body struct {
		ItemIDs []string `json:"itemIds"`
		Version string   `json:"version"`
	}
}

func (h *Handler) bulkPinCatalog(ctx context.Context, in *bulkPinCatalogInput) (*bulkResultsOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	res, err := h.svc.BulkPinCatalog(ctx, id.Subject, org.ID, in.Body.ItemIDs, in.Body.Version)
	if err != nil {
		return nil, mapErr(err)
	}
	out := &bulkResultsOutput{}
	out.Body.Results = res
	return out, nil
}
