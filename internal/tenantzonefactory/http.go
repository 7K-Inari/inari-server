// REST surface for the Tenant Zone Factory (plan §5.12): platform-
// engineer-only routes for vending, inspecting, resuming, and
// decommissioning tenant zones.
package tenantzonefactory

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

// Handler exposes the tenant zone REST surface.
type Handler struct {
	svc     *Service
	tenants TenantResolver
	authz   authz.Authorizer
}

// NewHandler builds the module handler.
func NewHandler(svc *Service, tenants TenantResolver, az authz.Authorizer) *Handler {
	return &Handler{svc: svc, tenants: tenants, authz: az}
}

// RegisterRoutes mounts the zone API on the huma API instance.
func (h *Handler) RegisterRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "requestTenantZone",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/zones",
		Summary:     "Request a new tenant zone (approval-gated by default)",
		Security:    httpserver.SecurityRequirement(),
	}, h.requestZone)

	huma.Register(api, huma.Operation{
		OperationID: "listTenantZones",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/zones",
		Summary:     "List tenant zones owned by this org",
		Security:    httpserver.SecurityRequirement(),
	}, h.listZones)

	huma.Register(api, huma.Operation{
		OperationID: "getTenantZone",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/zones/{id}",
		Summary:     "Get a tenant zone with its step sub-resources",
		Security:    httpserver.SecurityRequirement(),
	}, h.getZone)

	huma.Register(api, huma.Operation{
		OperationID: "resumeTenantZone",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/zones/{id}/resume",
		Summary:     "Resume a zone after manual intervention (§10)",
		Security:    httpserver.SecurityRequirement(),
	}, h.resumeZone)

	huma.Register(api, huma.Operation{
		OperationID: "decommissionTenantZone",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/zones/{id}/decommission",
		Summary:     "Decommission a tenant zone (approval-gated, ownership-checked)",
		Security:    httpserver.SecurityRequirement(),
	}, h.decommissionZone)
}

type requestZoneInput struct {
	Org  string `path:"org"`
	Body struct {
		Slug                string            `json:"slug" minLength:"3" maxLength:"32"`
		DisplayName         string            `json:"displayName" minLength:"1" maxLength:"100"`
		OUID                string            `json:"ouId" minLength:"1"`
		Region              string            `json:"region" minLength:"1"`
		Tier                string            `json:"tier" minLength:"1"`
		Tags                map[string]string `json:"tags,omitempty"`
		ManagementAccountID string            `json:"managementAccountId" minLength:"1"`
	}
}

type requestZoneOutput struct {
	Body struct {
		Zone       types.TenantZone `json:"zone"`
		ApprovalID string           `json:"approvalId,omitempty"`
	}
}

func (h *Handler) requestZone(ctx context.Context, in *requestZoneInput) (*requestZoneOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	res, err := h.svc.RequestZone(ctx, id.Subject, RequestInput{
		Slug: in.Body.Slug, DisplayName: in.Body.DisplayName, OUID: in.Body.OUID,
		Region: in.Body.Region, Tier: in.Body.Tier, Tags: in.Body.Tags,
		ManagementAccountID: in.Body.ManagementAccountID, OwnerOrgID: org.ID,
	})
	if errors.Is(err, ErrSlugTaken) {
		return nil, huma.Error409Conflict("zone slug already in use")
	}
	if err != nil {
		return nil, err
	}
	out := &requestZoneOutput{}
	out.Body.Zone = *res.Zone
	out.Body.ApprovalID = res.ApprovalID
	return out, nil
}

type orgPathInput struct {
	Org string `path:"org" doc:"Tenant slug (platform org owning the management account)"`
}

type listZonesOutput struct {
	Body struct {
		Zones []types.TenantZone `json:"zones"`
	}
}

func (h *Handler) listZones(ctx context.Context, in *orgPathInput) (*listZonesOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	zones, err := h.svc.ListZones(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	out := &listZonesOutput{}
	out.Body.Zones = zones
	return out, nil
}

type zonePathInput struct {
	Org string `path:"org"`
	ID  string `path:"id"`
}

type getZoneOutput struct {
	Body struct {
		Zone  types.TenantZone                 `json:"zone"`
		Steps map[string]*types.TenantZoneStep `json:"steps"`
	}
}

func (h *Handler) getZone(ctx context.Context, in *zonePathInput) (*getZoneOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	z, steps, err := h.svc.GetZone(ctx, in.ID)
	if errors.Is(err, ErrZoneNotFound) {
		return nil, huma.Error404NotFound("zone not found")
	}
	if err != nil {
		return nil, err
	}
	if z.OwnerOrgID != org.ID {
		return nil, huma.Error404NotFound("zone not found")
	}
	out := &getZoneOutput{}
	out.Body.Zone = *z
	out.Body.Steps = steps
	return out, nil
}

func (h *Handler) resumeZone(ctx context.Context, in *zonePathInput) (*struct{}, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	if err := h.requireOwnerOrg(ctx, org.ID, in.ID); err != nil {
		return nil, err
	}
	if err := h.svc.ResumeZone(ctx, in.ID, id.Subject); errors.Is(err, ErrInvalidState) {
		return nil, huma.Error409Conflict(err.Error())
	} else if err != nil {
		return nil, err
	}
	return nil, nil
}

type decommissionOutput struct {
	Body struct {
		ApprovalID string `json:"approvalId,omitempty"`
	}
}

func (h *Handler) decommissionZone(ctx context.Context, in *zonePathInput) (*decommissionOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	if err := h.requireOwnerOrg(ctx, org.ID, in.ID); err != nil {
		return nil, err
	}
	approvalID, err := h.svc.RequestDecommission(ctx, id.Subject, in.ID)
	if errors.Is(err, ErrInvalidState) {
		return nil, huma.Error409Conflict(err.Error())
	}
	if err != nil {
		return nil, err
	}
	out := &decommissionOutput{}
	out.Body.ApprovalID = approvalID
	return out, nil
}

func (h *Handler) requireOwnerOrg(ctx context.Context, orgID, zoneID string) error {
	z, err := h.svc.store.GetZone(ctx, h.svc.db.Pool, zoneID)
	if errors.Is(err, ErrZoneNotFound) {
		return huma.Error404NotFound("zone not found")
	}
	if err != nil {
		return err
	}
	if z.OwnerOrgID != orgID {
		return huma.Error404NotFound("zone not found")
	}
	return nil
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
