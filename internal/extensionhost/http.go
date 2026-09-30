// HTTP handlers for the extension host module (plan §5.8): the extension
// registry REST surface. The runtime proxy path /api/extensions/{name}/*
// lives in proxy.go (chi-mounted wildcard).
package extensionhost

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
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

// Handler exposes the extension registry REST surface.
type Handler struct {
	svc      *Service
	tenants  TenantResolver
	authz    authz.Authorizer
	fetcher  *RemoteEntryFetcher
	sessions SessionStore
}

func NewHandler(svc *Service, tenants TenantResolver, az authz.Authorizer) *Handler {
	return &Handler{svc: svc, tenants: tenants, authz: az}
}

// WithSessionStore wires the per-user third-party session store so the
// session bootstrap endpoint can persist oidc-sso-session material.
func (h *Handler) WithSessionStore(s SessionStore) *Handler {
	h.sessions = s
	return h
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
		OperationID: "rotateExtensionIdentity",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/extensions/{id}/identity/rotate",
		Summary:     "Rotate the extension's gateway identity secret (returned once; also lazily provisions identity for pre-ADR-0008 rows)",
		Security:    httpserver.SecurityRequirement(),
	}, h.rotateIdentity)
	huma.Register(api, huma.Operation{
		OperationID: "verifyExtension",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/extensions/{id}/verify",
		Summary:     "Run the SDK handshake and mark the extension ready",
		Security:    httpserver.SecurityRequirement(),
	}, h.verify)
	huma.Register(api, huma.Operation{
		OperationID: "putExtensionSession",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/extensions/{id}/session",
		Summary:     "Store bootstrapped third-party session material for the calling user (oidc-sso-session)",
		Security:    httpserver.SecurityRequirement(),
	}, h.putSession)
	huma.Register(api, huma.Operation{
		OperationID: "deleteExtensionSession",
		Method:      http.MethodDelete,
		Path:        "/api/v1/tenants/{org}/extensions/{id}/session",
		Summary:     "Drop the calling user's third-party session (logout/re-auth)",
		Security:    httpserver.SecurityRequirement(),
	}, h.deleteSession)
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
	huma.Register(api, huma.Operation{
		OperationID: "selfExtensionPermissions",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/authz/self/extensions",
		Summary:     "List the caller's effective extension invoke permissions",
		Security:    httpserver.SecurityRequirement(),
	}, h.selfExtensionPermissions)
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
	case errors.Is(err, ErrConflict):
		return huma.Error409Conflict(err.Error())
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
		// Credentials carries the extension's Keycloak client secret exactly
		// once (register responses only); it is never persisted server-side
		// and omitted from every other response (ADR-0008).
		Credentials *types.ExtensionCredentials `json:"credentials,omitempty"`
	}
}

func (h *Handler) register(ctx context.Context, in *registerInput) (*extensionOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationExtensionsManage)
	if err != nil {
		return nil, err
	}
	e, creds, err := h.svc.Register(ctx, id.Subject, RegisterInput{
		OrgID: org.ID, Name: in.Body.Name, Version: in.Body.Version, Kind: in.Body.Kind,
		Manifest: in.Body.Manifest, Endpoint: in.Body.Endpoint, Checksum: in.Body.Checksum,
	})
	if err != nil {
		return nil, mapErr(err)
	}
	out := &extensionOutput{}
	out.Body.Extension = *e
	out.Body.Credentials = creds
	return out, nil
}

type rotateIdentityOutput struct {
	Body struct {
		Credentials types.ExtensionCredentials `json:"credentials"`
	}
}

func (h *Handler) rotateIdentity(ctx context.Context, in *idInput) (*rotateIdentityOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationExtensionsManage)
	if err != nil {
		return nil, err
	}
	creds, err := h.svc.RotateIdentitySecret(ctx, id.Subject, org.ID, in.ID)
	if err != nil {
		return nil, mapErr(err)
	}
	out := &rotateIdentityOutput{}
	out.Body.Credentials = *creds
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
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantRead)
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
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantRead)
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
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationExtensionsManage)
	if err != nil {
		return nil, err
	}
	if err := h.svc.Unregister(ctx, id.Subject, org.ID, in.ID); err != nil {
		return nil, mapErr(err)
	}
	return nil, nil
}

func (h *Handler) verify(ctx context.Context, in *idInput) (*extensionOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationExtensionsManage)
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
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantRead)
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
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationExtensionsManage)
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
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationExtensionsManage)
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

// Self-permissions (§5.8): the console hides slots for extensions the caller
// may not invoke (inari-ui src/ext/rbac.ts). Returns the extension RBAC
// verbs ("extensions:invoke:<name>") the caller holds in this tenant. The
// FGA invoke relation already rolls up org roles (platform-engineer,
// developer) via the parent tuple, so per-extension checks suffice;
// extension counts per org are small.
type selfPermissionsOutput struct {
	Body struct {
		Permissions []string `json:"permissions"`
	}
}

func (h *Handler) selfExtensionPermissions(ctx context.Context, in *listUiInput) (*selfPermissionsOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantRead)
	if err != nil {
		return nil, err
	}
	exts, err := h.svc.List(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	out := &selfPermissionsOutput{}
	out.Body.Permissions = []string{}
	for i := range exts {
		ok, err := h.authz.Check(ctx, authz.UserObject(id.Subject), authz.RelationInvoke, authz.ExtensionObject(exts[i].ID))
		if err != nil {
			return nil, err
		}
		if ok {
			out.Body.Permissions = append(out.Body.Permissions, "extensions:invoke:"+exts[i].Name)
		}
	}
	return out, nil
}

// --- Per-user third-party sessions (oidc-sso-session bootstrap) ---

type sessionInput struct {
	Org  string `path:"org"`
	ID   string `path:"id"`
	Body struct {
		SessionMaterial  string `json:"sessionMaterial" doc:"third-party session credential; used for this call only, never echoed"`
		Nonce            string `json:"nonce,omitempty" doc:"client-generated replay marker"`
		ExpiresInSeconds int    `json:"expiresInSeconds,omitempty" doc:"override session TTL (capped); defaults to the token's exp claim or 8h"`
	}
}

type sessionOutput struct {
	Body struct {
		Session struct {
			ExtensionID string     `json:"extensionId"`
			State       string     `json:"state"`
			ExpiresAt   *time.Time `json:"expiresAt"`
		} `json:"session"`
	}
}

// sessionProviderFor derives the session provider key from the extension's
// declared default auth method (audience), falling back to the extension
// name — the same derivation the ssoSessionProvider uses at resolve time.
func sessionProviderFor(e *types.Extension) string {
	declared, err := pickAuthMethod(e)
	if err != nil {
		return e.Name
	}
	if declared.Audience != "" {
		return declared.Audience
	}
	return e.Name
}

// sessionExpiry prefers the material's own exp claim when it is JWT-shaped;
// otherwise it falls back to a bounded TTL. The claim is read best-effort
// without signature validation (the credential is opaque to us).
func sessionExpiry(material string, overrideSeconds int) time.Time {
	const defTTL, maxTTL = 8 * time.Hour, 24 * time.Hour
	if overrideSeconds > 0 {
		d := time.Duration(overrideSeconds) * time.Second
		if d > maxTTL {
			d = maxTTL
		}
		return time.Now().Add(d)
	}
	if exp, ok := jwtExpClaim(material); ok {
		return exp
	}
	return time.Now().Add(defTTL)
}

func jwtExpClaim(tok string) (time.Time, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Exp, 0), true
}

func (h *Handler) putSession(ctx context.Context, in *sessionInput) (*sessionOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationExtensionsInvoke)
	if err != nil {
		return nil, err
	}
	if h.sessions == nil {
		return nil, huma.Error501NotImplemented("extension sessions not configured")
	}
	if strings.TrimSpace(in.Body.SessionMaterial) == "" {
		return nil, huma.Error422UnprocessableEntity("sessionMaterial is required")
	}
	ext, err := h.svc.Get(ctx, org.ID, in.ID)
	if err != nil {
		return nil, mapErr(err)
	}
	provider := sessionProviderFor(ext)
	expiry := sessionExpiry(in.Body.SessionMaterial, in.Body.ExpiresInSeconds)
	material := in.Body.SessionMaterial
	in.Body.SessionMaterial = ""
	if err := h.sessions.Put(ctx, id.Subject, ext.Name, &UserSession{
		Provider: provider, Credential: material, Expiry: expiry,
	}); err != nil {
		return nil, mapErr(err)
	}
	out := &sessionOutput{}
	out.Body.Session.ExtensionID = ext.ID
	out.Body.Session.State = "active"
	out.Body.Session.ExpiresAt = &expiry
	return out, nil
}

type sessionPathInput struct {
	Org string `path:"org"`
	ID  string `path:"id"`
}

func (h *Handler) deleteSession(ctx context.Context, in *sessionPathInput) (*struct{}, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationExtensionsInvoke)
	if err != nil {
		return nil, err
	}
	if h.sessions == nil {
		return nil, huma.Error501NotImplemented("extension sessions not configured")
	}
	ext, err := h.svc.Get(ctx, org.ID, in.ID)
	if err != nil {
		return nil, mapErr(err)
	}
	if err := h.sessions.Delete(ctx, id.Subject, ext.Name, sessionProviderFor(ext)); err != nil {
		return nil, mapErr(err)
	}
	return &struct{}{}, nil
}
