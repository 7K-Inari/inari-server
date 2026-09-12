// Package auditapi exposes the org-scoped, filterable audit log REST surface
// (v1 feature "Audit log — every action, filterable, exportable", plan §7.1).
// It lives outside internal/audit because tenancy imports audit for the
// outbox, and the handler needs tenancy's sentinel errors.
package auditapi

import (
	"context"
	"encoding/csv"
	"errors"
	"net/http"
	"strings"

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

	huma.Register(api, huma.Operation{
		OperationID: "listAuditLog",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/audit",
		Summary:     "Org audit log in the console's shape (filterable by actor/action/objectType/from/to)",
		Security:    httpserver.SecurityRequirement(),
	}, h.listUI)

	huma.Register(api, huma.Operation{
		OperationID: "exportAuditLog",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/audit/export",
		Summary:     "Org audit log as CSV (same filters as the list)",
		Security:    httpserver.SecurityRequirement(),
	}, h.exportCSV)
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

// --- Console-compat surface (inari-ui src/api/audit.ts contract) ----------

// uiAuditEvent mirrors the console's AuditEvent shape exactly.
type uiAuditEvent struct {
	ID         string `json:"id"`
	Tenant     string `json:"tenant"`
	Actor      string `json:"actor"`
	Action     string `json:"action"`
	ObjectType string `json:"objectType"`
	ObjectName string `json:"objectName"`
	Detail     string `json:"detail"`
	At         string `json:"at"`
}

type listAuditUIInput struct {
	Org        string `path:"org"`
	Actor      string `query:"actor"`
	Action     string `query:"action"`
	ObjectType string `query:"objectType"`
	From       string `query:"from"`
	To         string `query:"to"`
	Limit      int    `query:"limit"`
}

type listAuditUIOutput struct {
	Body struct {
		Events []uiAuditEvent `json:"events"`
	}
}

func toUIEvents(slug string, events []types.AuditEvent) []uiAuditEvent {
	out := make([]uiAuditEvent, 0, len(events))
	for _, ev := range events {
		out = append(out, uiAuditEvent{
			ID:         ev.ID,
			Tenant:     slug,
			Actor:      ev.Actor,
			Action:     ev.Action,
			ObjectType: ev.ObjectType,
			ObjectName: ev.ObjectID,
			Detail:     string(ev.Payload),
			At:         ev.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}
	return out
}

func (h *Handler) listUI(ctx context.Context, in *listAuditUIInput) (*listAuditUIOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	events, err := h.store.ListFiltered(ctx, h.db.Pool, org.ID, audit.EventFilter{
		Action: in.Action, Actor: in.Actor, ObjectType: in.ObjectType, From: in.From, To: in.To, Limit: in.Limit,
	})
	if err != nil {
		return nil, err
	}
	out := &listAuditUIOutput{}
	out.Body.Events = toUIEvents(org.Slug, events)
	return out, nil
}

// exportCSV returns the same events as a text/csv download (raw body,
// same pattern as the cluster install-manifest endpoint).
func (h *Handler) exportCSV(ctx context.Context, in *listAuditUIInput) (*struct {
	ContentType string `header:"Content-Type"`
	Body        []byte
}, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	events, err := h.store.ListFiltered(ctx, h.db.Pool, org.ID, audit.EventFilter{
		Action: in.Action, Actor: in.Actor, ObjectType: in.ObjectType, From: in.From, To: in.To, Limit: in.Limit,
	})
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("id,tenant,actor,action,objectType,objectName,detail,at\n")
	cw := csv.NewWriter(&b)
	for _, ev := range toUIEvents(org.Slug, events) {
		_ = cw.Write([]string{ev.ID, ev.Tenant, ev.Actor, ev.Action, ev.ObjectType, ev.ObjectName, ev.Detail, ev.At})
	}
	cw.Flush()
	return &struct {
		ContentType string `header:"Content-Type"`
		Body        []byte
	}{ContentType: "text/csv; charset=utf-8", Body: []byte(b.String())}, nil
}
