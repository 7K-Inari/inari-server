// HTTP handlers for the extension host module (plan §5.8): the extension
// registry REST surface. The runtime proxy path /api/extensions/{name}/*
// lives in proxy.go (chi-mounted wildcard).
package extensionhost

import (
	"context"
	"encoding/json"
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

// Handler exposes the extension registry REST surface.
type Handler struct {
	svc     *Service
	tenants TenantResolver
	authz   authz.Authorizer
}

func NewHandler(svc *Service, tenants TenantResolver, az authz.Authorizer) *Handler {
	return &Handler{svc: svc, tenants: tenants, authz: az}
}

// RegisterRoutes mounts the extension registry API on the huma API instance.
func (h *Handler) RegisterRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "registerExtension",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/extensions",
		Summary:     "Register a backend extension (pending until handshake verifies)",
		Security:    httpserver.SecurityRequirement(),
	}, h.register)
	huma.Register(api, huma.Operation{
		OperationID: "listExtensions",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/extensions",
		Summary:     "List extensions",
		Security:    httpserver.SecurityRequirement(),
	}, h.list)
	huma.Register(api, huma.Operation{
		OperationID: "getExtension",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/extensions/{id}",
		Summary:     "Get an extension",
		Security:    httpserver.SecurityRequirement(),
	}, h.get)
	huma.Register(api, huma.Operation{
		OperationID: "unregisterExtension",
		Method:      http.MethodDelete,
		Path:        "/api/v1/tenants/{org}/extensions/{id}",
		Summary:     "Unregister an extension",
		Security:    httpserver.SecurityRequirement(),
	}, h.unregister)
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
	}
	return err
}

type registerInput struct {
	Org  string `path:"org"`
	Body struct {
		Name     string          `json:"name"`
		Version  string          `json:"version"`
		Kind     string          `json:"kind" doc:"backend"`
		Manifest json.RawMessage `json:"manifest,omitempty"`
		Endpoint string          `json:"endpoint" doc:"sidecar HTTP base URL (dial mode)"`
		Checksum string          `json:"checksum,omitempty" doc:"expected sha256 (hex) of the plugin artifact"`
	}
}

type extensionOutput struct {
	Body struct {
		Extension types.Extension `json:"extension"`
	}
}

func (h *Handler) register(ctx context.Context, in *registerInput) (*extensionOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	e, err := h.svc.Register(ctx, id.Subject, RegisterInput{
		OrgID: org.ID, Name: in.Body.Name, Version: in.Body.Version, Kind: in.Body.Kind,
		Manifest: in.Body.Manifest, Endpoint: in.Body.Endpoint, Checksum: in.Body.Checksum,
	})
	if err != nil {
		return nil, mapErr(err)
	}
	out := &extensionOutput{}
	out.Body.Extension = *e
	return out, nil
}

type listInput struct {
	Org string `path:"org"`
}

type listOutput struct {
	Body struct {
		Extensions []types.Extension `json:"extensions"`
	}
}

func (h *Handler) list(ctx context.Context, in *listInput) (*listOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	exts, err := h.svc.List(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	out := &listOutput{}
	out.Body.Extensions = exts
	return out, nil
}

type idInput struct {
	Org string `path:"org"`
	ID  string `path:"id"`
}

func (h *Handler) get(ctx context.Context, in *idInput) (*extensionOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	e, err := h.svc.Get(ctx, org.ID, in.ID)
	if err != nil {
		return nil, mapErr(err)
	}
	out := &extensionOutput{}
	out.Body.Extension = *e
	return out, nil
}

func (h *Handler) unregister(ctx context.Context, in *idInput) (*struct{}, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	if err := h.svc.Unregister(ctx, id.Subject, org.ID, in.ID); err != nil {
		return nil, mapErr(err)
	}
	return nil, nil
}
