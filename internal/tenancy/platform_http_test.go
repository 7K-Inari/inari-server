package tenancy

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/httpserver"
)

func newPlatformTestServer(t *testing.T, az *MeHandler, svc *Service, allow bool) *httptest.Server {
	t.Helper()
	router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(nil, nil)),
		stubValidator{id: &authn.Identity{Subject: "u1"}}, stubReady{})
	NewPlatformHandler(svc, flagAuthorizer{allow: allow}, "platform-admins").RegisterRoutes(api)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv
}

// The platform admins API is gated by org_creator on platform:inari; a
// caller without it gets 403 on every operation (service never touched, so
// a nil service is safe here).
func TestPlatformAdminsForbiddenWithoutOrgCreator(t *testing.T) {
	srv := newPlatformTestServer(t, nil, nil, false)
	for _, tc := range []struct{ method, url string }{
		{http.MethodGet, "/api/v1/platform/admins"},
		{http.MethodPut, "/api/v1/platform/admins/u2"},
		{http.MethodDelete, "/api/v1/platform/admins/u2"},
	} {
		resp := testTokenReq(t, tc.method, srv.URL+tc.url, "")
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s: got %d, want 403", tc.method, tc.url, resp.StatusCode)
		}
	}
}

func TestPlatformAdminsRequiresToken(t *testing.T) {
	srv := newPlatformTestServer(t, nil, nil, true)
	resp, err := http.Get(srv.URL + "/api/v1/platform/admins")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", resp.StatusCode)
	}
}
