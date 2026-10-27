// HTTP handlers for the addons module (Feature C, plan §6): the
// discover/adopt/update REST surface. Conventions mirror
// internal/gitrepos/http.go (huma operations, authorizeOrg, typed error →
// status mapping) and the orchestrator's repo-write enforcement
// (decision 5b).
package addons

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/clusterregistry"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/orchestrator"
	gitgithub "github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider/github"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

// TenantTeamResolver resolves tenant slugs and enumerates org teams
// (tenancy.Service seam for auth + team filtering).
type TenantTeamResolver interface {
	GetTenant(ctx context.Context, slug string) (*types.Organization, error)
	ListTeams(ctx context.Context, orgID string) ([]types.Team, error)
}

// RepoGetter resolves one registry repo row for the write-enforcement check
// (inventory.Store seam via adapter).
type RepoGetter interface {
	GetGitRepo(ctx context.Context, orgID, id string) (*types.TenantGitRepo, error)
}

// Handler exposes the addons REST surface.
type Handler struct {
	svc     *Service
	tenants TenantTeamResolver
	authz   authz.Authorizer
	// teams/repos enable the team-repo write enforcement (decision 5b).
	// nil = enforcement disabled (legacy wiring).
	teams TeamLister
	repos RepoGetter
}

// TeamLister resolves an org's teams for the repo-write enforcement check.
type TeamLister interface {
	ListTeams(ctx context.Context, orgID string) ([]types.Team, error)
}

// NewHandler wires the handler; WithRepoWriteEnforcement attaches the
// team-repo write check.
func NewHandler(svc *Service, tenants TenantTeamResolver, az authz.Authorizer) *Handler {
	return &Handler{svc: svc, tenants: tenants, authz: az}
}

// WithRepoWriteEnforcement wires the team-repo write check (decision 5b).
func (h *Handler) WithRepoWriteEnforcement(teams TeamLister, repos RepoGetter) *Handler {
	h.teams, h.repos = teams, repos
	return h
}

// RegisterRoutes mounts the addons API on the huma API instance.
func (h *Handler) RegisterRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "listClusterAddons",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/clusters/{c}/addons",
		Summary:     "List discovered + managed addons for a cluster (team-filtered, with available versions)",
		Security:    httpserver.SecurityRequirement(),
	}, h.list)

	huma.Register(api, huma.Operation{
		OperationID: "adoptAddon",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/clusters/{c}/addons/{catalogItem}/adopt",
		Summary:     "Adopt a (discovered or declared) addon into GitOps management",
		Security:    httpserver.SecurityRequirement(),
	}, h.adopt)

	huma.Register(api, huma.Operation{
		OperationID: "updateAddon",
		Method:      http.MethodPatch,
		Path:        "/api/v1/tenants/{org}/addons/{id}",
		Summary:     "Update a managed addon's chart version and/or values (commit per repo policy)",
		Security:    httpserver.SecurityRequirement(),
	}, h.update)

	huma.Register(api, huma.Operation{
		OperationID: "enableAddonPrune",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/addons/{id}/enable-prune",
		Summary:     "Explicitly enable prune on an adopted addon (audit-logged, one-directional)",
		Security:    httpserver.SecurityRequirement(),
	}, h.enablePrune)
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

// hasRelation is a fail-closed relation check (mirrors gitrepos).
func (h *Handler) hasRelation(ctx context.Context, subject, relation, orgID string) bool {
	ok, err := h.authz.Check(ctx, authz.UserObject(subject), relation, authz.OrgObject(orgID))
	return err == nil && ok
}

// listFilterForCaller returns nil (see all) for privileged callers,
// otherwise the caller's team IDs (decision 5).
func (h *Handler) listFilterForCaller(ctx context.Context, id *authn.Identity, orgID string) ([]string, error) {
	if h.hasRelation(ctx, id.Subject, authz.RelationTenantSettingsWrite, orgID) {
		return nil, nil
	}
	teams, err := h.tenants.ListTeams(ctx, orgID)
	if err != nil {
		return nil, err
	}
	return authn.CallerTeamIDs(id, teams), nil
}

// enforceRepoWrite implements the team-repo write check (decision 5b),
// mirroring the orchestrator: platform repos are writable by any org member
// with deployments_create (already checked by the caller); team repos
// require settings-write or owning-team membership. An empty repoID (org
// default / cluster baseline) skips the check.
func (h *Handler) enforceRepoWrite(ctx context.Context, id *authn.Identity, orgID, repoID string) error {
	if repoID == "" || h.teams == nil || h.repos == nil {
		return nil
	}
	row, err := h.repos.GetGitRepo(ctx, orgID, repoID)
	if errors.Is(err, inventory.ErrRepoNotFound) {
		return huma.Error404NotFound("git repo not found")
	}
	if err != nil {
		return err
	}
	if row.Scope == types.GitRepoScopePlatform {
		return nil
	}
	if h.hasRelation(ctx, id.Subject, authz.RelationTenantSettingsWrite, orgID) {
		return nil
	}
	teams, err := h.teams.ListTeams(ctx, orgID)
	if err != nil {
		return err
	}
	for _, t := range authn.CallerTeamIDs(id, teams) {
		if t == row.TeamID {
			return nil
		}
	}
	return huma.Error403Forbidden("not a member of the team that owns this repo")
}

// enforceAddonRepoWrite runs the repo-write check against the addon's
// recorded repo (mutations: update/enable-prune). Unknown addons defer to
// the service's own 404.
func (h *Handler) enforceAddonRepoWrite(ctx context.Context, id *authn.Identity, orgID, addonID string) error {
	row, err := h.svc.Get(ctx, orgID, addonID)
	if errors.Is(err, inventory.ErrAddonNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return h.enforceRepoWrite(ctx, id, orgID, row.RepoID)
}

// addonError maps service errors to HTTP statuses (mirrors the orchestrator
// and gitrepos mappings).
func addonError(err error) error {
	var ve *ValidationError
	if errors.As(err, &ve) {
		return huma.NewError(http.StatusUnprocessableEntity, ve.Error())
	}
	var notInstalled *gitgithub.ErrAppNotInstalled
	if errors.As(err, &notInstalled) {
		return huma.NewError(http.StatusPreconditionFailed, notInstalled.Error())
	}
	var revoked *gitgithub.ErrAppCredentialsRevoked
	if errors.As(err, &revoked) {
		return huma.NewError(http.StatusBadGateway, revoked.Error())
	}
	switch {
	case errors.Is(err, inventory.ErrAddonNotFound):
		return huma.Error404NotFound("addon not found")
	case errors.Is(err, inventory.ErrRepoNotFound):
		return huma.Error404NotFound("git repo not found")
	case errors.Is(err, catalog.ErrItemNotFound):
		return huma.Error404NotFound("catalog item not found")
	case errors.Is(err, catalog.ErrVersionNotFound):
		return huma.Error404NotFound("catalog item version not found")
	case errors.Is(err, clusterregistry.ErrClusterNotFound), errors.Is(err, orchestrator.ErrClusterMismatch):
		return huma.Error404NotFound("cluster not found")
	case errors.Is(err, ErrNoRepoConfig):
		return huma.Error409Conflict(err.Error())
	case errors.Is(err, ErrAlreadyManaged), errors.Is(err, ErrPruneAlreadyEnabled):
		return huma.Error409Conflict(err.Error())
	case errors.Is(err, ErrNotManaged):
		return huma.Error409Conflict(err.Error())
	case errors.Is(err, ErrNotDeployable), errors.Is(err, ErrEmptyFleet), errors.Is(err, ErrInvalidDeployMode):
		return huma.Error422UnprocessableEntity(err.Error())
	}
	return err
}

type listAddonsInput struct {
	Org     string `path:"org"`
	Cluster string `path:"c"`
}

type listAddonsOutput struct {
	Body struct {
		Addons []AddonView `json:"addons"`
	}
}

func (h *Handler) list(ctx context.Context, in *listAddonsInput) (*listAddonsOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantRead)
	if err != nil {
		return nil, err
	}
	filter, err := h.listFilterForCaller(ctx, id, org.ID)
	if err != nil {
		return nil, err
	}
	addons, err := h.svc.List(ctx, org.ID, in.Cluster, filter)
	if err != nil {
		return nil, addonError(err)
	}
	out := &listAddonsOutput{}
	out.Body.Addons = addons
	if out.Body.Addons == nil {
		out.Body.Addons = []AddonView{}
	}
	return out, nil
}

type adoptInput struct {
	Org         string `path:"org"`
	Cluster     string `path:"c"`
	CatalogItem string `path:"catalogItem"`
	Body        struct {
		RepoID          string            `json:"repoId,omitempty" doc:"tenant_git_repos row id; empty = the cluster's bound baseline"`
		Version         string            `json:"version,omitempty" doc:"catalog version (= chart version); empty = effective pin/latest stable"`
		Values          json.RawMessage   `json:"values,omitempty"`
		DeployMode      string            `json:"deployMode,omitempty" enum:"application,applicationset"`
		ClusterSelector map[string]string `json:"clusterSelector,omitempty" doc:"fleet label query (applicationset mode); empty = all org clusters"`
		Namespace       string            `json:"namespace,omitempty" pattern:"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" maxLength:"63"`
	}
}

type adoptOutput struct {
	Body struct {
		Addon     *types.ClusterAddon `json:"addon"`
		CommitSHA string              `json:"commitSha,omitempty"`
		PRURL     string              `json:"prUrl,omitempty"`
	}
}

func (h *Handler) adopt(ctx context.Context, in *adoptInput) (*adoptOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationDeploymentsCreate)
	if err != nil {
		return nil, err
	}
	if err := h.enforceRepoWrite(ctx, id, org.ID, in.Body.RepoID); err != nil {
		return nil, err
	}
	res, err := h.svc.Adopt(ctx, org.ID, in.Cluster, in.CatalogItem, AdoptInput{
		RepoID: in.Body.RepoID, Version: in.Body.Version, Values: in.Body.Values,
		DeployMode: types.AddonDeployMode(in.Body.DeployMode), ClusterSelector: in.Body.ClusterSelector,
		Namespace: in.Body.Namespace,
	}, "user:"+id.Subject)
	if err != nil {
		return nil, addonError(err)
	}
	out := &adoptOutput{}
	out.Body.Addon = res.Addon
	out.Body.CommitSHA = res.CommitSHA
	out.Body.PRURL = res.PRURL
	return out, nil
}

type updateAddonInput struct {
	Org  string `path:"org"`
	ID   string `path:"id"`
	Body struct {
		ChartVersion *string          `json:"chartVersion,omitempty"`
		Values       *json.RawMessage `json:"values,omitempty"`
	}
}

func (h *Handler) update(ctx context.Context, in *updateAddonInput) (*adoptOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationDeploymentsCreate)
	if err != nil {
		return nil, err
	}
	if in.Body.ChartVersion == nil && in.Body.Values == nil {
		return nil, huma.Error422UnprocessableEntity("chartVersion and/or values required")
	}
	if err := h.enforceAddonRepoWrite(ctx, id, org.ID, in.ID); err != nil {
		return nil, err
	}
	res, err := h.svc.Update(ctx, org.ID, in.ID, UpdateInput{
		ChartVersion: in.Body.ChartVersion, Values: in.Body.Values,
	}, "user:"+id.Subject)
	if err != nil {
		return nil, addonError(err)
	}
	out := &adoptOutput{}
	out.Body.Addon = res.Addon
	out.Body.CommitSHA = res.CommitSHA
	out.Body.PRURL = res.PRURL
	return out, nil
}

type enablePruneInput struct {
	Org string `path:"org"`
	ID  string `path:"id"`
}

func (h *Handler) enablePrune(ctx context.Context, in *enablePruneInput) (*adoptOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationDeploymentsCreate)
	if err != nil {
		return nil, err
	}
	if err := h.enforceAddonRepoWrite(ctx, id, org.ID, in.ID); err != nil {
		return nil, err
	}
	res, err := h.svc.EnablePrune(ctx, org.ID, in.ID, "user:"+id.Subject)
	if err != nil {
		return nil, addonError(err)
	}
	out := &adoptOutput{}
	out.Body.Addon = res.Addon
	out.Body.CommitSHA = res.CommitSHA
	out.Body.PRURL = res.PRURL
	return out, nil
}
