//go:build integration

package policyservice_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/policyservice"
	"github.com/7K-Inari/inari-server/internal/types"
)

// relationGate grants a fixed role on any org object (fine PEP stub),
// modeling the OpenFGA hierarchy: admin ⇒ platform_engineer ⇒ viewer.
type relationGate struct{ relation string }

func (g relationGate) Check(_ context.Context, _, relation, _ string) (bool, error) {
	switch g.relation {
	case "admin":
		return relation == "admin" || relation == "platform_engineer" || relation == "viewer", nil
	case "platform_engineer":
		return relation == "platform_engineer" || relation == "viewer", nil
	}
	return relation == g.relation, nil
}
func (g relationGate) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

type fixedValidator struct{ id *authn.Identity }

func (v fixedValidator) Validate(context.Context, string) (*authn.Identity, error) { return v.id, nil }

type readyOK struct{}

func (readyOK) Ping(context.Context) error { return nil }

type staticTenants struct {
	orgs map[string]*types.Organization
}

func (s staticTenants) GetTenant(_ context.Context, slug string) (*types.Organization, error) {
	if o, ok := s.orgs[slug]; ok {
		return o, nil
	}
	return nil, fmt.Errorf("unknown org %q", slug)
}

func newPolicyServer(t *testing.T, svc *policyservice.Service, id *authn.Identity, relation string) *httptest.Server {
	t.Helper()
	router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), fixedValidator{id: id}, readyOK{})
	tenants := staticTenants{orgs: map[string]*types.Organization{
		"acme": {ID: "org:1", Slug: "acme", DisplayName: "Acme"},
	}}
	policyservice.NewHandler(svc, tenants, relationGate{relation: relation}).RegisterRoutes(api)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv
}

func doReq(t *testing.T, srv *httptest.Server, method, path, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer good")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

func newQAPack(t *testing.T, svc *policyservice.Service, name string) *types.PolicyPack {
	t.Helper()
	manifests := json.RawMessage(`[{"apiVersion":"kyverno.io/v1","kind":"ClusterPolicy","metadata":{"name":"require-labels"}}]`)
	pack, err := svc.CreatePolicyPack(context.Background(), "user-1", "org:1", name, types.PolicyPackEngineKyverno, "", "1.0.0", nil, manifests)
	if err != nil {
		t.Fatal(err)
	}
	return pack
}

func TestPolicyPackDeleteAndAssignmentsHTTP(t *testing.T) {
	svc, _, database := itService(t)
	ctx := context.Background()

	member := &authn.Identity{Subject: "user-1", Organizations: []string{"acme"}}
	stranger := &authn.Identity{Subject: "user-9", Organizations: []string{"other"}}
	adminSrv := newPolicyServer(t, svc, member, "admin")
	engSrv := newPolicyServer(t, svc, member, "platform_engineer")
	strangerSrv := newPolicyServer(t, svc, stranger, "admin")

	packPath := func(id string) string { return "/api/v1/tenants/acme/policy-packs/" + id }

	t.Run("coarse PEP rejects non-member on both routes", func(t *testing.T) {
		pack := newQAPack(t, svc, "coarse-pep")
		if code, _ := doReq(t, strangerSrv, http.MethodGet, packPath(pack.ID)+"/assignments", ""); code != http.StatusForbidden {
			t.Errorf("stranger GET assignments: got %d, want 403", code)
		}
		if code, _ := doReq(t, strangerSrv, http.MethodDelete, packPath(pack.ID)+"?force=true", ""); code != http.StatusForbidden {
			t.Errorf("stranger DELETE: got %d, want 403", code)
		}
	})

	t.Run("fine PEP: platform_engineer reads but cannot delete", func(t *testing.T) {
		pack := newQAPack(t, svc, "fine-pep")
		if code, body := doReq(t, engSrv, http.MethodGet, packPath(pack.ID)+"/assignments", ""); code != http.StatusOK || !strings.Contains(body, `"assignments"`) {
			t.Errorf("engineer GET assignments: got %d %s, want 200", code, body)
		}
		if code, _ := doReq(t, engSrv, http.MethodDelete, packPath(pack.ID), ""); code != http.StatusForbidden {
			t.Errorf("engineer DELETE: got %d, want 403", code)
		}
	})

	t.Run("assigned pack: 409 with structured list, then force deletes", func(t *testing.T) {
		pack := newQAPack(t, svc, "conflict-flow")
		a, err := svc.Assign(ctx, "user-1", "org:1", pack.ID, types.PolicyTargetCluster, "cluster:1")
		if err != nil {
			t.Fatal(err)
		}
		// GET lists the assignment with the documented fields.
		code, body := doReq(t, adminSrv, http.MethodGet, packPath(pack.ID)+"/assignments", "")
		if code != http.StatusOK {
			t.Fatalf("GET assignments: %d %s", code, body)
		}
		if !strings.Contains(body, a.ID) || !strings.Contains(body, `"targetType":"cluster"`) ||
			!strings.Contains(body, `"targetId":"cluster:1"`) || !strings.Contains(body, `"createdAt"`) {
			t.Errorf("assignments body missing fields: %s", body)
		}
		// DELETE without force -> 409 naming the assignment.
		code, body = doReq(t, adminSrv, http.MethodDelete, packPath(pack.ID), "")
		if code != http.StatusConflict {
			t.Fatalf("DELETE no force: got %d %s, want 409", code, body)
		}
		if !strings.Contains(body, a.ID) {
			t.Errorf("409 body does not name assignment %s: %s", a.ID, body)
		}
		// Pack still there.
		if code, _ := doReq(t, adminSrv, http.MethodGet, packPath(pack.ID), ""); code != http.StatusOK {
			t.Errorf("pack gone after refused delete: %d", code)
		}
		// force=true cascades.
		if code, body := doReq(t, adminSrv, http.MethodDelete, packPath(pack.ID)+"?force=true", ""); code != http.StatusNoContent {
			t.Fatalf("force DELETE: got %d %s, want 204", code, body)
		}
		// Pack and assignments gone.
		if code, _ := doReq(t, adminSrv, http.MethodGet, packPath(pack.ID), ""); code != http.StatusNotFound {
			t.Errorf("pack after force delete: %d, want 404", code)
		}
		if code, body := doReq(t, adminSrv, http.MethodGet, packPath(pack.ID)+"/assignments", ""); code != http.StatusNotFound {
			t.Errorf("assignments after force delete: %d %s, want 404", code, body)
		}
		// Re-delete is a 404, not a 5xx.
		if code, body := doReq(t, adminSrv, http.MethodDelete, packPath(pack.ID)+"?force=true", ""); code != http.StatusNotFound {
			t.Errorf("re-delete: got %d %s, want 404", code, body)
		}
	})

	t.Run("unassigned pack deletes without force", func(t *testing.T) {
		pack := newQAPack(t, svc, "clean-delete")
		if code, body := doReq(t, adminSrv, http.MethodDelete, packPath(pack.ID), ""); code != http.StatusNoContent {
			t.Fatalf("DELETE: got %d %s, want 204", code, body)
		}
	})

	t.Run("force with truthy variants and garbage", func(t *testing.T) {
		p1 := newQAPack(t, svc, "force-1")
		if code, body := doReq(t, adminSrv, http.MethodDelete, packPath(p1.ID)+"?force=1", ""); code != http.StatusNoContent {
			t.Errorf("force=1: got %d %s, want 204", code, body)
		}
		p2 := newQAPack(t, svc, "force-2")
		code, _ := doReq(t, adminSrv, http.MethodDelete, packPath(p2.ID)+"?force=garbage", "")
		if code == http.StatusNoContent {
			t.Error("force=garbage was accepted as true; want 4xx")
		}
		if code >= 500 {
			t.Errorf("force=garbage: got %d, want 4xx validation error", code)
		}
	})

	t.Run("unknown pack 404s on both routes", func(t *testing.T) {
		if code, _ := doReq(t, adminSrv, http.MethodGet, packPath("policypack:nope")+"/assignments", ""); code != http.StatusNotFound {
			t.Errorf("GET assignments missing pack: %d, want 404", code)
		}
		if code, _ := doReq(t, adminSrv, http.MethodDelete, packPath("policypack:nope"), ""); code != http.StatusNotFound {
			t.Errorf("DELETE missing pack: %d, want 404", code)
		}
	})

	t.Run("concurrent force deletes: one 200, rest 404, no 5xx", func(t *testing.T) {
		pack := newQAPack(t, svc, "race")
		const n = 8
		var wg sync.WaitGroup
		codes := make([]int, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				code, _ := doReq(t, adminSrv, http.MethodDelete, packPath(pack.ID)+"?force=true", "")
				codes[i] = code
			}(i)
		}
		wg.Wait()
		ok, notFound := 0, 0
		for _, c := range codes {
			switch c {
			case http.StatusNoContent:
				ok++
			case http.StatusNotFound:
				notFound++
			default:
				t.Errorf("concurrent delete returned %d, want 204 or 404 (codes=%v)", c, codes)
			}
		}
		if ok != 1 || notFound != n-1 {
			t.Errorf("concurrent deletes: ok=%d notFound=%d, want 1/%d (codes=%v)", ok, notFound, n-1, codes)
		}
	})

	t.Run("concurrent assign + force delete never 5xx and ends consistent", func(t *testing.T) {
		pack := newQAPack(t, svc, "race-assign")
		if _, err := svc.Assign(ctx, "user-1", "org:1", pack.ID, types.PolicyTargetCluster, "cluster:1"); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var delCode int
		wg.Add(2)
		go func() {
			defer wg.Done()
			delCode, _ = doReq(t, adminSrv, http.MethodDelete, packPath(pack.ID)+"?force=true", "")
		}()
		go func() {
			defer wg.Done()
			// Assign may fail if the pack disappears first — acceptable.
			_, _ = svc.Assign(ctx, "user-1", "org:1", pack.ID, types.PolicyTargetCluster, "cluster:2")
		}()
		wg.Wait()
		if delCode >= 500 {
			t.Errorf("delete during concurrent assign: %d, want non-5xx", delCode)
		}
		// Final state must be consistent: pack gone, zero assignments remain.
		if _, err := svc.GetPolicyPack(ctx, "org:1", pack.ID); err == nil {
			t.Error("pack survived force delete")
		}
		var count int
		if err := database.Pool.QueryRow(ctx,
			`SELECT count(*) FROM policy_assignments WHERE pack_id = $1`, pack.ID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Errorf("%d orphaned assignments after force delete", count)
		}
	})
}
