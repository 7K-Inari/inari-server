package tenancy

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/httpserver"
)

type stubValidator struct{ id *authn.Identity }

func (s stubValidator) Validate(context.Context, string) (*authn.Identity, error) { return s.id, nil }

type stubReady struct{}

func (stubReady) Ping(context.Context) error { return nil }

type flagAuthorizer struct{ allow bool }

func (f flagAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	if object == authz.ObjectPlatform && relation == authz.RelationOrgCreator {
		return f.allow, nil
	}
	return false, nil
}

func (f flagAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

func newMeTestServer(t *testing.T, az authz.Authorizer) *httptest.Server {
	t.Helper()
	router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(nil, nil)),
		stubValidator{id: &authn.Identity{Subject: "u1"}}, stubReady{})
	NewMeHandler(az).RegisterRoutes(api)
	NewHandler(nil, az).RegisterRoutes(api)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv
}

func testTokenReq(t *testing.T, method, url, body string) *http.Response {
	t.Helper()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer good")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestMyPermissionsAllowed(t *testing.T) {
	srv := newMeTestServer(t, flagAuthorizer{allow: true})
	resp := testTokenReq(t, http.MethodGet, srv.URL+"/api/v1/me/permissions", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	var body struct {
		CanCreateOrganizations bool `json:"canCreateOrganizations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if !body.CanCreateOrganizations {
		t.Error("canCreateOrganizations = false, want true")
	}
}

func TestMyPermissionsDenied(t *testing.T) {
	srv := newMeTestServer(t, flagAuthorizer{allow: false})
	resp := testTokenReq(t, http.MethodGet, srv.URL+"/api/v1/me/permissions", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	var body struct {
		CanCreateOrganizations bool `json:"canCreateOrganizations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.CanCreateOrganizations {
		t.Error("canCreateOrganizations = true, want false")
	}
}

func TestMyPermissionsRequiresToken(t *testing.T) {
	srv := newMeTestServer(t, flagAuthorizer{allow: true})
	resp, err := http.Get(srv.URL + "/api/v1/me/permissions")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", resp.StatusCode)
	}
}

func TestCreateTenantForbiddenWithoutOrgCreator(t *testing.T) {
	srv := newMeTestServer(t, flagAuthorizer{allow: false})
	resp := testTokenReq(t, http.MethodPost, srv.URL+"/api/v1/tenants",
		`{"slug":"acme","displayName":"Acme"}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got %d, want 403", resp.StatusCode)
	}
	var body struct {
		Detail string `json:"detail"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body.Detail, "org_creator") {
		t.Errorf("detail = %q, want org_creator mention", body.Detail)
	}
}
