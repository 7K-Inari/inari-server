// remoteEntry.js asset route (plan §5.8): mounted on chi directly (like the
// extension proxy) since it serves a JavaScript stream, not a JSON huma
// operation. The route is intentionally unauthenticated: the Module
// Federation runtime loads remote entries via <script> injection, which
// carries no Authorization header. The payload is client-side JavaScript
// (not secret); integrity is enforced hub-side (checksum pin / cosign on OCI
// sources), the registry list stays viewer-authed, and disabled extensions
// are not served.
package extensionhost

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

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
	fetcher *RemoteEntryFetcher
}

func NewUiAssetServer(svc UiRegistry, tenants TenantResolver, f *RemoteEntryFetcher) *UiAssetServer {
	return &UiAssetServer{svc: svc, tenants: tenants, fetcher: f}
}

// Mount registers the asset route on the chi router.
func (s *UiAssetServer) Mount(r chi.Router) {
	r.Get("/api/v1/tenants/{org}/extensions/ui/{name}/remoteEntry.js", s.ServeHTTP)
}

func (s *UiAssetServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	org, err := s.tenants.GetTenant(r.Context(), chi.URLParam(r, "org"))
	if errors.Is(err, tenancy.ErrOrgNotFound) {
		http.Error(w, `{"detail":"organization not found"}`, http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, `{"detail":"tenant resolution failed"}`, http.StatusInternalServerError)
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
	body, err := s.fetcher.Fetch(r.Context(), e.Ui)
	if err != nil {
		http.Error(w, `{"detail":"remoteEntry unavailable"}`, http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=60")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
