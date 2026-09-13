//go:build integration

package policyservice_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/policyservice"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

type qaPERelAuthz struct{ allow bool }

func (a qaPERelAuthz) Check(_ context.Context, _, relation, _ string) (bool, error) {
	return a.allow && relation == authz.RelationPlatformEngineer, nil
}
func (a qaPERelAuthz) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

// TestUpdatePolicyHTTP exercises PUT /tenants/{org}/policies/{id}
// end-to-end: authz, 404, 409 rename conflict, 422 broken rego, happy path.
func TestUpdatePolicyHTTP(t *testing.T) {
	svc, _, database := itService(t)
	ctx := context.Background()
	tenants := tenancy.NewService(database, nil, tenancy.NewStore(), audit.NewStore())
	if _, err := database.Pool.Exec(ctx,
		`INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ('org:qa-pol','qa-pol','QA Pol','kc-qapol')`); err != nil {
		t.Fatal(err)
	}
	org, err := tenants.GetTenant(ctx, "qa-pol")
	if err != nil {
		t.Fatal(err)
	}

	mkServer := func(id *authn.Identity, allow bool) *httptest.Server {
		router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)),
			qaFixedValidator{id: id}, readyQOK{})
		policyservice.NewHandler(svc, tenants, qaPERelAuthz{allow: allow}).RegisterRoutes(api)
		srv := httptest.NewServer(router)
		t.Cleanup(srv.Close)
		return srv
	}
	member := &authn.Identity{Subject: "user-1", Organizations: []string{"qa-pol"}}

	p, err := svc.CreatePolicy(ctx, "user-1", org.ID, "first", types.PolicyTargetRequest, types.PolicyEngineRego, itDenyRego)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreatePolicy(ctx, "user-1", org.ID, "second", types.PolicyTargetRequest, types.PolicyEngineRego, itDenyRego); err != nil {
		t.Fatal(err)
	}

	put := func(srv *httptest.Server, id, body string) *http.Response {
		req, err := http.NewRequest(http.MethodPut,
			srv.URL+"/api/v1/tenants/qa-pol/policies/"+id, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer good")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}

	srv := mkServer(member, true)

	// Member without the platform-engineer tuple -> 403.
	if resp := put(mkServer(member, false), p.ID, `{"enabled":true,"source":"package inari.policy"}`); resp.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(resp.Body)
		t.Errorf("non-PE: got %d, want 403 (%s)", resp.StatusCode, b)
	}
	// Unknown policy -> 404.
	if resp := put(srv, "policy:nope", `{"enabled":true,"source":"package inari.policy"}`); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown policy: got %d, want 404", resp.StatusCode)
	}
	// Rename conflict -> 409.
	if resp := put(srv, p.ID, `{"name":"second","enabled":true,"source":"`+regoJSON(itDenyRego)+`"}`); resp.StatusCode != http.StatusConflict {
		t.Errorf("rename conflict: got %d, want 409", resp.StatusCode)
	}
	// Broken rego -> 422.
	if resp := put(srv, p.ID, `{"enabled":true,"source":"package inari.policy\n\ndeny if {"}`); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("broken rego: got %d, want 422", resp.StatusCode)
	}
	// Bad target -> 422.
	if resp := put(srv, p.ID, `{"target":"bogus","enabled":true,"source":"`+regoJSON(itDenyRego)+`"}`); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("bad target: got %d, want 422", resp.StatusCode)
	}
	// Happy path: rename + retarget + disable -> 200, version bumped.
	resp := put(srv, p.ID, `{"name":"first-v2","target":"render","enabled":false,"source":"`+regoJSON(itDenyRego)+`"}`)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("happy path: got %d (%s)", resp.StatusCode, b)
	}
	var out struct {
		Policy types.Policy `json:"policy"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Policy.Name != "first-v2" || out.Policy.Target != types.PolicyTargetRender ||
		out.Policy.Enabled || out.Policy.Version != 2 {
		t.Errorf("updated policy = %+v", out.Policy)
	}
}

func regoJSON(s string) string {
	b, _ := json.Marshal(s)
	return strings.Trim(string(b), `"`)
}

type qaFixedValidator struct{ id *authn.Identity }

func (v qaFixedValidator) Validate(context.Context, string) (*authn.Identity, error) {
	return v.id, nil
}

type readyQOK struct{}

func (readyQOK) Ping(context.Context) error { return nil }
