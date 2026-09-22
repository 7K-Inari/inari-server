// remoteEntry.js asset route (plan §5.8): mounted on chi directly (like the
// extension proxy) since it serves a JavaScript stream, not a JSON huma
// operation. The caller must be a tenant viewer; descriptors carrying
// requiredPermission additionally enforce the FGA invoke relation
// (extensions:invoke:<name>).
package extensionhost

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

// UiRegistry resolves UI extension records by org + name (Service seam).
type UiRegistry interface {
	GetUi(ctx context.Context, orgID, name string) (*types.Extension, error)
}

// UiAssetServer serves GET /api/v1/tenants/{org}/extensions/ui/{name}/remoteEntry.js.
type UiAssetServer struct {
	svc     UiRegistry
	tenants TenantResolver
	auth    authn.Validator
	az      authz.Authorizer
	fetcher *RemoteEntryFetcher
}

func NewUiAssetServer(svc UiRegistry, tenants TenantResolver, v authn.Validator, az authz.Authorizer, f *RemoteEntryFetcher) *UiAssetServer {
	return &UiAssetServer{svc: svc, tenants: tenants, auth: v, az: az, fetcher: f}
}

// Mount registers the asset route on the chi router.
func (s *UiAssetServer) Mount(r chi.Router) {
	r.Get("/api/v1/tenants/{org}/extensions/ui/{name}/remoteEntry.js", s.ServeHTTP)
}

func (s *UiAssetServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const prefix = "Bearer "
	raw := r.Header.Get("Authorization")
	if len(raw) <= len(prefix) || !strings.EqualFold(raw[:len(prefix)], prefix) {
		http.Error(w, `{"detail":"missing or malformed authorization header"}`, http.StatusUnauthorized)
		return
	}
	id, err := s.auth.Validate(r.Context(), raw[len(prefix):])
	if err != nil {
		http.Error(w, `{"detail":"invalid token"}`, http.StatusUnauthorized)
		return
	}
	slug := chi.URLParam(r, "org")
	if !id.MemberOf(slug) {
		http.Error(w, `{"detail":"not a member of this organization"}`, http.StatusForbidden)
		return
	}
	org, err := s.tenants.GetTenant(r.Context(), slug)
	if errors.Is(err, tenancy.ErrOrgNotFound) {
		http.Error(w, `{"detail":"organization not found"}`, http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, `{"detail":"tenant resolution failed"}`, http.StatusInternalServerError)
		return
	}
	ok, err := s.az.Check(r.Context(), authz.UserObject(id.Subject), authz.RelationViewer, authz.OrgObject(org.ID))
	if err != nil {
		http.Error(w, `{"detail":"authorization check failed"}`, http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, `{"detail":"insufficient permissions"}`, http.StatusForbidden)
		return
	}
	e, err := s.svc.GetUi(r.Context(), org.ID, chi.URLParam(r, "name"))
	if err != nil {
		http.Error(w, `{"detail":"extension not found"}`, http.StatusNotFound)
		return
	}
	if !e.Ui.Enabled {
		http.Error(w, `{"detail":"extension disabled"}`, http.StatusNotFound)
		return
	}
	if e.Ui.RequiredPermission != "" {
		allowed, err := s.az.Check(r.Context(), authz.UserObject(id.Subject), authz.RelationInvoke, authz.ExtensionObject(e.ID))
		if err != nil {
			http.Error(w, `{"detail":"authorization check failed"}`, http.StatusInternalServerError)
			return
		}
		if !allowed {
			http.Error(w, `{"detail":"forbidden"}`, http.StatusForbidden)
			return
		}
	}
	body, err := s.fetcher.Fetch(r.Context(), e.Ui)
	if err != nil {
		http.Error(w, `{"detail":"remoteEntry unavailable"}`, http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "private, max-age=60")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
