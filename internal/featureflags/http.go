package featureflags

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

// ClusterGetter loads one cluster (clusterregistry.Service) for the
// ownership check on cluster-scoped routes.
type ClusterGetter interface {
	GetCluster(ctx context.Context, id string) (*types.Cluster, error)
}

// Handler exposes the feature-flags REST surface: platform-scoped defaults
// (platform admins) and cluster-scoped overrides (tenant admin/operator via
// the clusters.register relation).
type Handler struct {
	svc          *Service
	resolver     *Resolver
	tenants      TenantResolver
	clusters     ClusterGetter
	authz        authz.Authorizer
	envOverrides map[string]bool
}

// NewHandler builds the handler. Nil-safe: with svc nil the routes register
// (OpenAPI export) but answer 501.
func NewHandler(svc *Service, resolver *Resolver, tenants TenantResolver, clusters ClusterGetter, az authz.Authorizer, envOverrides map[string]bool) *Handler {
	if envOverrides == nil {
		envOverrides = map[string]bool{}
	}
	return &Handler{svc: svc, resolver: resolver, tenants: tenants, clusters: clusters, authz: az, envOverrides: envOverrides}
}

// FlagView is one flag's catalog entry plus its effective/persisted state.
type FlagView struct {
	Key         string `json:"key"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Default     bool   `json:"default"`
	// Value is the effective value for the requested scope.
	Value bool `json:"value"`
	// Overridden reports a persisted row at the requested scope.
	Overridden bool `json:"overridden"`
	// EnvPinned reports that an explicitly set env override wins over any
	// runtime value (writes are accepted but inert).
	EnvPinned bool `json:"envPinned"`
}

// RegisterRoutes mounts the feature-flags API on the huma API instance.
func (h *Handler) RegisterRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "listPlatformFeatureFlags",
		Method:      http.MethodGet,
		Path:        "/api/v1/platform/feature-flags",
		Summary:     "List the runtime feature-flag catalog with platform effective values",
		Security:    httpserver.SecurityRequirement(),
	}, h.listPlatform)

	huma.Register(api, huma.Operation{
		OperationID: "setPlatformFeatureFlag",
		Method:      http.MethodPut,
		Path:        "/api/v1/platform/feature-flags/{key}",
		Summary:     "Set a platform-scoped feature-flag value",
		Security:    httpserver.SecurityRequirement(),
	}, h.setPlatform)

	huma.Register(api, huma.Operation{
		OperationID: "clearPlatformFeatureFlag",
		Method:      http.MethodDelete,
		Path:        "/api/v1/platform/feature-flags/{key}",
		Summary:     "Revert a platform-scoped feature flag to its built-in default",
		Security:    httpserver.SecurityRequirement(),
	}, h.clearPlatform)

	huma.Register(api, huma.Operation{
		OperationID: "listClusterFeatureFlags",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/clusters/{id}/feature-flags",
		Summary:     "List the feature-flag catalog with per-cluster effective values",
		Security:    httpserver.SecurityRequirement(),
	}, h.listCluster)

	huma.Register(api, huma.Operation{
		OperationID: "setClusterFeatureFlag",
		Method:      http.MethodPut,
		Path:        "/api/v1/tenants/{org}/clusters/{id}/feature-flags/{key}",
		Summary:     "Set a cluster-scoped feature-flag override (tenant admin/operator)",
		Security:    httpserver.SecurityRequirement(),
	}, h.setCluster)

	huma.Register(api, huma.Operation{
		OperationID: "clearClusterFeatureFlag",
		Method:      http.MethodDelete,
		Path:        "/api/v1/tenants/{org}/clusters/{id}/feature-flags/{key}",
		Summary:     "Revert a cluster-scoped feature-flag override to the platform default",
		Security:    httpserver.SecurityRequirement(),
	}, h.clearCluster)
}

// authorizePlatform gates platform-scope routes on org_creator on
// platform:inari (same PEP as the platform admins API).
func (h *Handler) authorizePlatform(ctx context.Context) (string, error) {
	id := httpserver.IdentityFromContext(ctx)
	if id == nil {
		return "", huma.Error401Unauthorized("unauthenticated")
	}
	ok, err := h.authz.Check(ctx, authz.UserObject(id.Subject), authz.RelationOrgCreator, authz.ObjectPlatform)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", huma.Error403Forbidden("platform feature flags require the platform org_creator permission")
	}
	return id.Subject, nil
}

// authorizeCluster performs coarse PEP (org claim) + fine PEP (OpenFGA) +
// the cluster ownership check, mirroring clusterregistry.authorizeOrg.
func (h *Handler) authorizeCluster(ctx context.Context, slug, clusterID, relation string) (*types.Organization, *authn.Identity, error) {
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
	c, err := h.clusters.GetCluster(ctx, clusterID)
	if err != nil || c.OrgID != org.ID {
		return nil, nil, huma.Error404NotFound("cluster not found")
	}
	return org, id, nil
}

func (h *Handler) requireService() error {
	if h.svc == nil {
		return huma.Error501NotImplemented("feature flags store not configured")
	}
	return nil
}

func (h *Handler) view(ctx context.Context, def Definition, scope Scope, scopeKey string) (FlagView, error) {
	v := FlagView{
		Key:         def.Key,
		Type:        string(def.Type),
		Description: def.Description,
		Default:     def.Default,
	}
	if _, pinned := h.envOverrides[def.Key]; pinned {
		v.EnvPinned = true
	}
	if h.resolver == nil {
		v.Value = def.Default
	} else if scope == ScopeCluster {
		v.Value = h.resolver.Bool(ctx, def.Key, scopeKey)
	} else {
		v.Value = h.resolver.Bool(ctx, def.Key, "")
	}
	row, err := h.svc.Get(ctx, def.Key, scope, scopeKey)
	if err != nil {
		return v, err
	}
	if row != nil {
		v.Overridden = true
	}
	return v, nil
}

type listFlagsOutput struct {
	Body struct {
		Flags []FlagView `json:"flags"`
	}
}

func (h *Handler) listPlatform(ctx context.Context, _ *struct{}) (*listFlagsOutput, error) {
	if _, err := h.authorizePlatform(ctx); err != nil {
		return nil, err
	}
	if err := h.requireService(); err != nil {
		return nil, err
	}
	out := &listFlagsOutput{}
	for _, def := range Catalog() {
		if !def.AllowsScope(ScopePlatform) {
			continue
		}
		v, err := h.view(ctx, def, ScopePlatform, "")
		if err != nil {
			return nil, err
		}
		out.Body.Flags = append(out.Body.Flags, v)
	}
	return out, nil
}

type setFlagInput struct {
	Key  string `path:"key"`
	Body struct {
		Value bool `json:"value"`
	}
}

func (h *Handler) setPlatform(ctx context.Context, in *setFlagInput) (*struct{}, error) {
	actor, err := h.authorizePlatform(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.requireService(); err != nil {
		return nil, err
	}
	err = h.svc.Set(ctx, actor, "", in.Key, ScopePlatform, "", in.Body.Value)
	return nil, writeError(err)
}

type flagKeyInput struct {
	Key string `path:"key"`
}

func (h *Handler) clearPlatform(ctx context.Context, in *flagKeyInput) (*struct{}, error) {
	actor, err := h.authorizePlatform(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.requireService(); err != nil {
		return nil, err
	}
	err = h.svc.Clear(ctx, actor, "", in.Key, ScopePlatform, "")
	return nil, writeError(err)
}

type clusterFlagsInput struct {
	Org string `path:"org"`
	ID  string `path:"id"`
}

func (h *Handler) listCluster(ctx context.Context, in *clusterFlagsInput) (*listFlagsOutput, error) {
	if _, _, err := h.authorizeCluster(ctx, in.Org, in.ID, authz.RelationTenantRead); err != nil {
		return nil, err
	}
	if err := h.requireService(); err != nil {
		return nil, err
	}
	out := &listFlagsOutput{}
	for _, def := range Catalog() {
		if !def.AllowsScope(ScopeCluster) {
			continue
		}
		v, err := h.view(ctx, def, ScopeCluster, in.ID)
		if err != nil {
			return nil, err
		}
		out.Body.Flags = append(out.Body.Flags, v)
	}
	return out, nil
}

type setClusterFlagInput struct {
	Org  string `path:"org"`
	ID   string `path:"id"`
	Key  string `path:"key"`
	Body struct {
		Value bool `json:"value"`
	}
}

func (h *Handler) setCluster(ctx context.Context, in *setClusterFlagInput) (*struct{}, error) {
	org, id, err := h.authorizeCluster(ctx, in.Org, in.ID, authz.RelationClustersRegister)
	if err != nil {
		return nil, err
	}
	if err := h.requireService(); err != nil {
		return nil, err
	}
	err = h.svc.Set(ctx, id.Subject, org.ID, in.Key, ScopeCluster, in.ID, in.Body.Value)
	return nil, writeError(err)
}

type clearClusterFlagInput struct {
	Org string `path:"org"`
	ID  string `path:"id"`
	Key string `path:"key"`
}

func (h *Handler) clearCluster(ctx context.Context, in *clearClusterFlagInput) (*struct{}, error) {
	org, id, err := h.authorizeCluster(ctx, in.Org, in.ID, authz.RelationClustersRegister)
	if err != nil {
		return nil, err
	}
	if err := h.requireService(); err != nil {
		return nil, err
	}
	err = h.svc.Clear(ctx, id.Subject, org.ID, in.Key, ScopeCluster, in.ID)
	return nil, writeError(err)
}

func writeError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrUnknownFlag):
		return huma.Error404NotFound("unknown feature flag")
	case errors.Is(err, ErrBadScope):
		return huma.Error422UnprocessableEntity("flag does not allow this scope")
	default:
		return err
	}
}
