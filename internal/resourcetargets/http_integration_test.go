//go:build integration

package resourcetargets

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
)

type targetValidator struct{}

func (targetValidator) Validate(_ context.Context, token string) (*authn.Identity, error) {
	switch token {
	case "admin":
		return &authn.Identity{Subject: "admin", Organizations: []string{"store"}}, nil
	case "alice":
		return &authn.Identity{Subject: "alice", Organizations: []string{"store"}}, nil
	case "outsider":
		return &authn.Identity{Subject: "outsider", Organizations: []string{"other"}}, nil
	default:
		return nil, errors.New("invalid token")
	}
}

func targetRequest(t *testing.T, srv *httptest.Server, method, path, token, body string) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, srv.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, raw
}

func TestHTTPTargetAdministrationAndEntitlementFilteredReads(t *testing.T) {
	svc, database, az, teamID, _ := serviceFixture(t)
	az.managerSubjects = map[string]bool{"user:admin": true}
	tenants := tenancy.NewService(database, nil, tenancy.NewStore(), nil)
	router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), targetValidator{}, database)
	NewHandler(svc, tenants, az).RegisterRoutes(api)
	srv := httptest.NewServer(router)
	defer srv.Close()

	if code, _ := targetRequest(t, srv, http.MethodGet, "/api/v1/tenants/store/resource-targets", "", ""); code != http.StatusUnauthorized {
		t.Errorf("unauthenticated list = %d, want 401", code)
	}
	if code, _ := targetRequest(t, srv, http.MethodGet, "/api/v1/tenants/store/resource-targets", "outsider", ""); code != http.StatusForbidden {
		t.Errorf("outsider list = %d, want 403", code)
	}
	code, body := targetRequest(t, srv, http.MethodGet, "/api/v1/tenants/store/resource-target-providers", "alice", "")
	if code != http.StatusOK || !strings.Contains(string(body), CapabilityMonitoringGrafana) {
		t.Fatalf("providers = %d %s", code, body)
	}

	create := `{"name":"deployment","resourceRef":{"kind":"cluster","id":"cluster:store"},"capability":"deployment.cluster","config":{}}`
	code, body = targetRequest(t, srv, http.MethodPost, "/api/v1/tenants/store/resource-targets", "alice", create)
	if code != http.StatusForbidden {
		t.Fatalf("non-manager create = %d %s, want 403", code, body)
	}
	code, body = targetRequest(t, srv, http.MethodPost, "/api/v1/tenants/store/resource-targets", "admin", create)
	if code != http.StatusOK {
		t.Fatalf("manager create = %d %s", code, body)
	}
	var created struct {
		Target Target `json:"target"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	targetID := created.Target.ID
	if targetID == "" || created.Target.Revision != 1 {
		t.Fatalf("created target = %+v", created.Target)
	}

	code, body = targetRequest(t, srv, http.MethodPut,
		"/api/v1/tenants/store/resource-targets/"+targetID+"/grants/"+teamID, "admin", `{"relation":"use"}`)
	if code != http.StatusOK {
		t.Fatalf("set grant = %d %s", code, body)
	}
	az.allow("alice", targetID, "viewer")
	az.allow("alice", targetID, "use")
	code, body = targetRequest(t, srv, http.MethodGet, "/api/v1/tenants/store/resource-targets?action=use", "alice", "")
	if code != http.StatusOK || !strings.Contains(string(body), targetID) {
		t.Fatalf("entitled list = %d %s", code, body)
	}
	code, body = targetRequest(t, srv, http.MethodGet, "/api/v1/tenants/store/resource-targets/"+targetID, "alice", "")
	if code != http.StatusOK {
		t.Fatalf("entitled get = %d %s", code, body)
	}

	code, body = targetRequest(t, srv, http.MethodPatch, "/api/v1/tenants/store/resource-targets/"+targetID, "admin",
		`{"name":"renamed","revision":99}`)
	if code != http.StatusConflict {
		t.Fatalf("stale revision = %d %s, want 409", code, body)
	}

	code, _ = targetRequest(t, srv, http.MethodDelete,
		"/api/v1/tenants/store/resource-targets/"+targetID+"/grants/"+teamID, "admin", "")
	if code != http.StatusOK {
		t.Fatalf("revoke grant = %d", code)
	}
	// The fake FGA allow intentionally remains stale; the DB fence must hide
	// the target immediately.
	code, _ = targetRequest(t, srv, http.MethodGet, "/api/v1/tenants/store/resource-targets/"+targetID, "alice", "")
	if code != http.StatusNotFound {
		t.Errorf("get after revocation = %d, want 404", code)
	}
	code, body = targetRequest(t, srv, http.MethodGet, "/api/v1/tenants/store/resource-targets?action=use", "alice", "")
	if code != http.StatusOK || strings.Contains(string(body), targetID) {
		t.Errorf("list after revocation = %d %s", code, body)
	}
}
