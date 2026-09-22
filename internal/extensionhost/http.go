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
	fetcher *RemoteEntryFetcher
}

func NewHandler(svc *Service, tenants TenantResolver, az authz.Authorizer) *Handler {
	return &Handler{svc: svc, tenants: tenants, authz: az}
}

// WithRemoteEntryFetcher wires the remoteEntry cache so registration writes
// invalidate stale assets.
func (h *Handler) WithRemoteEntryFetcher(f *RemoteEntryFetcher) *Handler {
	h.fetcher = f
	return h
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
	huma.Register(api, huma.Operation{
		OperationID: "verifyExtension",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/extensions/{id}/verify",
		Summary:     "Run the SDK handshake and mark the extension ready",
		Security:    httpserver.SecurityRequirement(),
	}, h.verify)
	huma.Register(api, huma.Operation{
		OperationID: "listUiExtensions",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/extensions/ui",
		Summary:     "List UI extensions (Module Federation remotes)",
		Security:    httpserver.SecurityRequirement(),
	}, h.listUi)
	huma.Register(api, huma.Operation{
		OperationID: "registerUiExtension",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/extensions/ui",
		Summary:     "Register or update a UI extension remote",
		Security:    httpserver.SecurityRequirement(),
	}, h.registerUi)
	huma.Register(api, huma.Operation{
		OperationID: "unregisterUiExtension",
		Method:      http.MethodDelete,
		Path:        "/api/v1/tenants/{org}/extensions/ui/{name}",
		Summary:     "Unregister a UI extension remote",
		Security:    httpserver.SecurityRequirement(),
	}, h.unregisterUi)
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

func (h *Handler) verify(ctx context.Context, in *idInput) (*extensionOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	e, err := h.svc.Verify(ctx, id.Subject, org.ID, in.ID)
	if err != nil {
		return nil, mapErr(err)
	}
	out := &extensionOutput{}
	out.Body.Extension = *e
	return out, nil
}

/* UI extension registry (§5.8) -------------------------------------------- */

// UiExtensionRemote is the console-facing projection of a UI extension
// record (inari-ui UiExtensionRemote). RemoteEntryURL always points at the
// control-plane-served asset — never the registered upstream URL.
type UiExtensionRemote struct {
	Name               string                   `json:"name"`
	Version            string                   `json:"version"`
	Title              string                   `json:"title,omitempty"`
	Description        string                   `json:"description,omitempty"`
	RemoteEntryURL     string                   `json:"remoteEntryUrl"`
	Slots              []types.UiSlotDescriptor `json:"slots"`
	RequiredPermission string                   `json:"requiredPermission,omitempty"`
	Enabled            bool                     `json:"enabled"`
}

func uiRemote(orgSlug string, e *types.Extension) UiExtensionRemote {
	d := e.Ui
	return UiExtensionRemote{
		Name: e.Name, Version: e.Version, Title: d.Title, Description: d.Description,
		RemoteEntryURL: "/api/v1/tenants/" + orgSlug + "/extensions/ui/" + e.Name + "/remoteEntry.js",
		Slots:          d.Slots, RequiredPermission: d.RequiredPermission, Enabled: d.Enabled,
	}
}

type listUiInput struct {
	Org string `path:"org"`
}

type listUiOutput struct {
	Body struct {
		Extensions []UiExtensionRemote `json:"extensions"`
	}
}

func (h *Handler) listUi(ctx context.Context, in *listUiInput) (*listUiOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	exts, err := h.svc.ListUi(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	out := &listUiOutput{}
	out.Body.Extensions = make([]UiExtensionRemote, 0, len(exts))
	for i := range exts {
		out.Body.Extensions = append(out.Body.Extensions, uiRemote(org.Slug, &exts[i]))
	}
	return out, nil
}

type registerUiInput struct {
	Org  string `path:"org"`
	Body struct {
		Name    string `json:"name"`
		Version string `json:"version,omitempty"`
		// RemoteEntryURL is the console client's field name; RemoteEntry is
		// the manifest (extension.yaml spec.ui.remoteEntry) name. Exactly one
		// of these or RemoteEntryOci must be set.
		RemoteEntryURL     string                   `json:"remoteEntryUrl,omitempty"`
		RemoteEntry        string                   `json:"remoteEntry,omitempty"`
		RemoteEntryOci     string                   `json:"remoteEntryOci,omitempty"`
		Checksum           string                   `json:"checksum,omitempty"`
		Title              string                   `json:"title,omitempty"`
		Description        string                   `json:"description,omitempty"`
		RequiredPermission string                   `json:"requiredPermission,omitempty"`
		Slots              []types.UiSlotDescriptor `json:"slots,omitempty"`
		Enabled            *bool                    `json:"enabled,omitempty"`
	}
}

type uiExtensionOutput struct {
	Body struct {
		Extension UiExtensionRemote `json:"extension"`
	}
}

func (h *Handler) registerUi(ctx context.Context, in *registerUiInput) (*uiExtensionOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	remoteEntry := in.Body.RemoteEntry
	if remoteEntry == "" {
		remoteEntry = in.Body.RemoteEntryURL
	}
	version := in.Body.Version
	if version == "" {
		version = "0.0.0"
	}
	// Invalidate the stale asset before the upsert: the cache is keyed by the
	// descriptor, so invalidating the post-update record is a no-op and would
	// orphan the old entry until the TTL.
	prev, err := h.svc.GetUi(ctx, org.ID, in.Body.Name)
	if err == nil {
		h.invalidateUiCache(prev)
	}
	e, err := h.svc.RegisterUi(ctx, id.Subject, RegisterUiInput{
		OrgID: org.ID, Name: in.Body.Name, Version: version,
		RemoteEntry: remoteEntry, RemoteEntryOci: in.Body.RemoteEntryOci,
		Checksum: in.Body.Checksum, Title: in.Body.Title, Description: in.Body.Description,
		RequiredPermission: in.Body.RequiredPermission, Slots: in.Body.Slots, Enabled: in.Body.Enabled,
	})
	if err != nil {
		return nil, mapErr(err)
	}
	out := &uiExtensionOutput{}
	out.Body.Extension = uiRemote(org.Slug, e)
	return out, nil
}

type uiNameInput struct {
	Org  string `path:"org"`
	Name string `path:"name"`
}

func (h *Handler) unregisterUi(ctx context.Context, in *uiNameInput) (*struct{}, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	e, err := h.svc.GetUi(ctx, org.ID, in.Name)
	if err != nil {
		return nil, mapErr(err)
	}
	if err := h.svc.UnregisterUi(ctx, id.Subject, org.ID, in.Name); err != nil {
		return nil, mapErr(err)
	}
	h.invalidateUiCache(e)
	return nil, nil
}

func (h *Handler) invalidateUiCache(e *types.Extension) {
	if h.fetcher != nil && e != nil {
		h.fetcher.Invalidate(e.Ui)
	}
}
