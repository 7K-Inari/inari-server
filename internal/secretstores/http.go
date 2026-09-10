// HTTP handlers for the secret-stores module (Settings design §3.2).
package secretstores

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

// Handler exposes the secret-stores REST surface.
type Handler struct {
	svc     *Service
	tenants TenantResolver
	authz   authz.Authorizer
}

func NewHandler(svc *Service, tenants TenantResolver, az authz.Authorizer) *Handler {
	return &Handler{svc: svc, tenants: tenants, authz: az}
}

// RegisterRoutes mounts the secret-stores API on the huma API instance.
func (h *Handler) RegisterRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "listSecretStores",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/secret-stores",
		Summary:     "List secret stores (own cluster-scoped plus platform stores)",
		Security:    httpserver.SecurityRequirement(),
	}, h.list)

	huma.Register(api, huma.Operation{
		OperationID: "createSecretStore",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/secret-stores",
		Summary:     "Register a secret store",
		Security:    httpserver.SecurityRequirement(),
	}, h.create)

	huma.Register(api, huma.Operation{
		OperationID: "getSecretStore",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/secret-stores/{name}",
		Summary:     "Get one secret store",
		Security:    httpserver.SecurityRequirement(),
	}, h.get)

	huma.Register(api, huma.Operation{
		OperationID: "updateSecretStore",
		Method:      http.MethodPatch,
		Path:        "/api/v1/tenants/{org}/secret-stores/{name}",
		Summary:     "Update a secret store's targets/provider",
		Security:    httpserver.SecurityRequirement(),
	}, h.update)

	huma.Register(api, huma.Operation{
		OperationID: "deleteSecretStore",
		Method:      http.MethodDelete,
		Path:        "/api/v1/tenants/{org}/secret-stores/{name}",
		Summary:     "Delete a secret store",
		Security:    httpserver.SecurityRequirement(),
	}, h.delete)

	huma.Register(api, huma.Operation{
		OperationID: "getSecretStoreStatus",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/secret-stores/{name}/status",
		Summary:     "Delivery status projection for one secret store",
		Security:    httpserver.SecurityRequirement(),
	}, h.status)
}

// authorizeOrg gates org membership + relation, mirroring the other tenant
// route handlers (gateway does coarse PEP, this is the fine PEP).
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

// isSuperuser reports whether the caller holds superuser on platform:inari.
// Platform-scope writes are platform-team operations on top of org admin.
func (h *Handler) isSuperuser(ctx context.Context, id *authn.Identity) bool {
	ok, err := h.authz.Check(ctx, authz.UserObject(id.Subject), authz.RelationSuperuser, authz.ObjectPlatform)
	return err == nil && ok
}

type listInput struct {
	Org string `path:"org"`
}

type listOutput struct {
	Body struct {
		Stores []types.SecretStore `json:"stores"`
	}
}

func (h *Handler) list(ctx context.Context, in *listInput) (*listOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	stores, err := h.svc.List(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	out := &listOutput{}
	out.Body.Stores = stores
	return out, nil
}

type createInput struct {
	Org  string `path:"org"`
	Body struct {
		Name     string                    `json:"name"`
		Scope    string                    `json:"scope"`
		Targets  types.SecretStoreTargets  `json:"targets"`
		Provider types.SecretStoreProvider `json:"provider"`
	}
}

type storeOutput struct {
	Body struct {
		Store types.SecretStore `json:"store"`
	}
}

func (h *Handler) create(ctx context.Context, in *createInput) (*storeOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin)
	if err != nil {
		return nil, err
	}
	if in.Body.Scope == types.SecretStoreScopePlatform && !h.isSuperuser(ctx, id) {
		return nil, huma.Error403Forbidden("platform-scoped stores require platform superuser")
	}
	st, err := h.svc.Create(ctx, "user:"+id.Subject, types.SecretStore{
		OrgID:    org.ID,
		Name:     in.Body.Name,
		Scope:    in.Body.Scope,
		Targets:  in.Body.Targets,
		Provider: in.Body.Provider,
	})
	if errors.Is(err, ErrInvalidInput) {
		return nil, huma.Error422UnprocessableEntity(err.Error())
	}
	if errors.Is(err, ErrConflict) {
		return nil, huma.Error409Conflict("secret store name already exists")
	}
	if err != nil {
		return nil, err
	}
	out := &storeOutput{}
	out.Body.Store = *st
	return out, nil
}

type storePathInput struct {
	Org  string `path:"org"`
	Name string `path:"name"`
}

func (h *Handler) get(ctx context.Context, in *storePathInput) (*storeOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	st, err := h.svc.Get(ctx, org.ID, in.Name)
	if errors.Is(err, ErrNotFound) {
		return nil, huma.Error404NotFound("secret store not found")
	}
	if err != nil {
		return nil, err
	}
	out := &storeOutput{}
	out.Body.Store = *st
	return out, nil
}

// authorizePlatformWrite loads the store and enforces the platform-scope
// gate: writes to platform stores by non-superusers are 403.
func (h *Handler) authorizePlatformWrite(ctx context.Context, orgID string, id *authn.Identity, name string) (*types.SecretStore, error) {
	st, err := h.svc.Get(ctx, orgID, name)
	if errors.Is(err, ErrNotFound) {
		return nil, huma.Error404NotFound("secret store not found")
	}
	if err != nil {
		return nil, err
	}
	if st.Scope == types.SecretStoreScopePlatform && !h.isSuperuser(ctx, id) {
		return nil, huma.Error403Forbidden("platform-scoped stores require platform superuser")
	}
	return st, nil
}

type updateInput struct {
	Org  string `path:"org"`
	Name string `path:"name"`
	Body struct {
		Targets  *types.SecretStoreTargets  `json:"targets,omitempty"`
		Provider *types.SecretStoreProvider `json:"provider,omitempty"`
	}
}

func (h *Handler) update(ctx context.Context, in *updateInput) (*storeOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin)
	if err != nil {
		return nil, err
	}
	if _, err := h.authorizePlatformWrite(ctx, org.ID, id, in.Name); err != nil {
		return nil, err
	}
	st, err := h.svc.Update(ctx, "user:"+id.Subject, org.ID, in.Name, in.Body.Targets, in.Body.Provider)
	if errors.Is(err, ErrNotFound) {
		return nil, huma.Error404NotFound("secret store not found")
	}
	if errors.Is(err, ErrInvalidInput) {
		return nil, huma.Error422UnprocessableEntity(err.Error())
	}
	if err != nil {
		return nil, err
	}
	out := &storeOutput{}
	out.Body.Store = *st
	return out, nil
}

func (h *Handler) delete(ctx context.Context, in *storePathInput) (*struct{}, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin)
	if err != nil {
		return nil, err
	}
	if _, err := h.authorizePlatformWrite(ctx, org.ID, id, in.Name); err != nil {
		return nil, err
	}
	if err := h.svc.Delete(ctx, "user:"+id.Subject, org.ID, in.Name); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, huma.Error404NotFound("secret store not found")
		}
		return nil, err
	}
	return nil, nil
}

type statusOutput struct {
	Body struct {
		Status types.SecretStoreStatus `json:"status"`
	}
}

func (h *Handler) status(ctx context.Context, in *storePathInput) (*statusOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	st, err := h.svc.Status(ctx, org.ID, in.Name)
	if errors.Is(err, ErrNotFound) {
		return nil, huma.Error404NotFound("secret store not found")
	}
	if err != nil {
		return nil, err
	}
	out := &statusOutput{}
	out.Body.Status = *st
	return out, nil
}
