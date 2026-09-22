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
	"strings"

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
	// Webpack remotes emit async chunks next to remoteEntry.js; serve them
	// from the same source directory (single safe filename, no checksum —
	// the entry's integrity pin already anchors the origin).
	r.Get("/api/v1/tenants/{org}/extensions/ui/{name}/*", s.ServeAsset)
}

func (s *UiAssetServer) resolveOrg(w http.ResponseWriter, r *http.Request) (*types.Organization, *types.Extension, bool) {
	org, err := s.tenants.GetTenant(r.Context(), chi.URLParam(r, "org"))
	if errors.Is(err, tenancy.ErrOrgNotFound) {
		http.Error(w, `{"detail":"organization not found"}`, http.StatusNotFound)
		return nil, nil, false
	}
	if err != nil {
		http.Error(w, `{"detail":"tenant resolution failed"}`, http.StatusInternalServerError)
		return nil, nil, false
	}
	e, err := s.svc.GetUi(r.Context(), org.ID, chi.URLParam(r, "name"))
	if err != nil {
		http.Error(w, `{"detail":"extension not found"}`, http.StatusNotFound)
		return nil, nil, false
	}
	if !e.Ui.Enabled {
		http.Error(w, `{"detail":"extension disabled"}`, http.StatusNotFound)
		return nil, nil, false
	}
	return org, e, true
}

// ServeAsset serves a sibling asset of the remote entry (webpack chunks).
func (s *UiAssetServer) ServeAsset(w http.ResponseWriter, r *http.Request) {
	_, e, ok := s.resolveOrg(w, r)
	if !ok {
		return
	}
	file := strings.TrimPrefix(r.URL.Path, "/api/v1/tenants/"+chi.URLParam(r, "org")+"/extensions/ui/"+chi.URLParam(r, "name")+"/")
	body, err := s.fetcher.FetchAsset(r.Context(), e.Ui, file)
	if err != nil {
		http.Error(w, `{"detail":"asset unavailable"}`, http.StatusBadGateway)
		return
	}
	ctype := "application/octet-stream"
	switch {
	case strings.HasSuffix(file, ".js"):
		ctype = "application/javascript; charset=utf-8"
	case strings.HasSuffix(file, ".map"):
		ctype = "application/json; charset=utf-8"
	case strings.HasSuffix(file, ".css"):
		ctype = "text/css; charset=utf-8"
	case strings.HasSuffix(file, ".txt"):
		ctype = "text/plain; charset=utf-8"
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", "public, max-age=60")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
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
