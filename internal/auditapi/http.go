// Package auditapi exposes the org-scoped, filterable audit log REST surface
// (v1 feature "Audit log — every action, filterable, exportable", plan §7.1).
// It lives outside internal/audit because tenancy imports audit for the
// outbox, and the handler needs tenancy's sentinel errors.
package auditapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

// TenantResolver resolves a tenant slug to its record (tenancy.Service).
type TenantResolver interface {
	GetTenant(ctx context.Context, slug string) (*types.Organization, error)
}

// Handler exposes the audit REST surface.
type Handler struct {
	db      *db.DB
	store   *audit.Store
	tenants TenantResolver
	authz   authz.Authorizer
}

func NewHandler(d *db.DB, store *audit.Store, tenants TenantResolver, az authz.Authorizer) *Handler {
	return &Handler{db: d, store: store, tenants: tenants, authz: az}
}

// RegisterRoutes mounts the audit API on the huma API instance.
func (h *Handler) RegisterRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "listAuditEvents",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/audit-events",
		Summary:     "List org audit events, newest first (filterable by action and actor)",
		Security:    httpserver.SecurityRequirement(),
	}, h.list)
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

type listEventsInput struct {
	Org    string `path:"org"`
	Action string `query:"action" doc:"Exact action filter, e.g. cluster.created"`
	Actor  string `query:"actor" doc:"Exact actor (subject) filter"`
	Limit  int    `query:"limit" doc:"Max events to return (default 100, max 500)"`
}

type listEventsOutput struct {
	Body struct {
		Events []types.AuditEvent `json:"events"`
	}
}

func (h *Handler) list(ctx context.Context, in *listEventsInput) (*listEventsOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	events, err := h.store.ListFiltered(ctx, h.db.Pool, org.ID, audit.EventFilter{
		Action: in.Action, Actor: in.Actor, Limit: in.Limit,
	})
	if err != nil {
		return nil, err
	}
	out := &listEventsOutput{}
	out.Body.Events = events
	if out.Body.Events == nil {
		out.Body.Events = []types.AuditEvent{}
	}
	return out, nil
}
