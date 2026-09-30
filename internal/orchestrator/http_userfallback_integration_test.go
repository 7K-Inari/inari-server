//go:build integration

package orchestrator_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/7K-Inari/inari-server/internal/approvals"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/orchestrator"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

// recordingAuthorizer captures the relation of each Check (guard-wiring
// assertions) while allowing everything.
type recordingAuthorizer struct {
	mu        sync.Mutex
	relations []string
}

func (a *recordingAuthorizer) Check(_ context.Context, _, relation, _ string) (bool, error) {
	a.mu.Lock()
	a.relations = append(a.relations, relation)
	a.mu.Unlock()
	return true, nil
}

func (a *recordingAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

func (a *recordingAuthorizer) saw(relation string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, r := range a.relations {
		if r == relation {
			return true
		}
	}
	return false
}

// TestGitConfigUserTemplateFallback covers the M8.W6 fallback-policy API:
// platform-engineer guard wiring, 422 validation, round-trip, and
// preserve-on-omit semantics.
func TestGitConfigUserTemplateFallback(t *testing.T) {
	ctx := context.Background()
	database := itDatabase(t)
	az := &recordingAuthorizer{}
	auditStore := audit.NewStore()
	tenancySvc := tenancy.NewService(database, nil, tenancy.NewStore(), auditStore)
	catalogSvc := catalog.NewService(database, catalog.NewStore(), nil, auditStore, nil)
	approvalsSvc := approvals.NewService(database, approvals.NewStore(database), auditStore, tenancySvc, catalogSvc)
	fake := gitprovider.NewFake()
	orchSvc := orchestrator.NewService(database, inventory.NewStore(), catalogSvc, itClusters{},
		approvalsSvc, &itQueue{}, gitprovider.StaticResolver{P: fake}, auditStore)
	router, api := httpserver.NewRouter(slog.Default(), itValidator{}, database)
	orchestrator.NewHandler(orchSvc, itTenants{"acme": {ID: "org:1", Slug: "acme"}}, az).RegisterRoutes(api)
	srv := httptest.NewServer(router)
	defer srv.Close()

	// 422: invalid policy value.
	code, body := itReq(t, srv, "PUT", "/api/v1/tenants/acme/git-config", "good",
		`{"repo":"acme/acme-inari-state","userTemplateFallback":"team_app"}`)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid fallback: %d %s", code, body)
	}

	// platform_app round-trips; the PUT must be guarded by
	// RelationTenantSettingsWrite (admin-only policy update).
	code, body = itReq(t, srv, "PUT", "/api/v1/tenants/acme/git-config", "good",
		`{"repo":"acme/acme-inari-state","commitPolicy":"direct","userTemplateFallback":"platform_app"}`)
	if code != http.StatusOK && code != http.StatusNoContent {
		t.Fatalf("set fallback: %d %s", code, body)
	}
	if !az.saw(authz.RelationTenantSettingsWrite) {
		t.Fatal("git-config PUT must check RelationTenantSettingsWrite")
	}
	code, body = itReq(t, srv, "GET", "/api/v1/tenants/acme/git-config", "good", "")
	if code != http.StatusOK {
		t.Fatalf("get git config: %d %s", code, body)
	}
	var out struct {
		Config types.TenantGitConfig `json:"config"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Config.UserTemplateFallback != "platform_app" {
		t.Fatalf("fallback = %q, want platform_app", out.Config.UserTemplateFallback)
	}

	// Preserve-on-omit: a writer that doesn't set the field (TZF-style
	// upsert) must not reset the stored policy.
	code, body = itReq(t, srv, "PUT", "/api/v1/tenants/acme/git-config", "good",
		`{"repo":"acme/acme-inari-state","commitPolicy":"direct"}`)
	if code != http.StatusOK && code != http.StatusNoContent {
		t.Fatalf("plain upsert: %d %s", code, body)
	}
	inv := inventory.NewStore()
	cfg, err := inv.GitConfig(ctx, database.Pool, "org:1")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UserTemplateFallback != "platform_app" {
		t.Fatalf("fallback wiped by plain upsert: %q", cfg.UserTemplateFallback)
	}

	// Boundary: an explicit empty string must behave like omit (preserve
	// the stored policy), not fail validation or reset to block.
	code, body = itReq(t, srv, "PUT", "/api/v1/tenants/acme/git-config", "good",
		`{"repo":"acme/acme-inari-state","commitPolicy":"direct","userTemplateFallback":""}`)
	if code != http.StatusOK && code != http.StatusNoContent {
		t.Fatalf("explicit-empty upsert: %d %s", code, body)
	}
	cfg, err = inv.GitConfig(ctx, database.Pool, "org:1")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UserTemplateFallback != "platform_app" {
		t.Fatalf("fallback changed by explicit-empty upsert: %q", cfg.UserTemplateFallback)
	}

	// Boundary: policy values are case-sensitive ("BLOCK" is invalid).
	code, body = itReq(t, srv, "PUT", "/api/v1/tenants/acme/git-config", "good",
		`{"repo":"acme/acme-inari-state","userTemplateFallback":"BLOCK"}`)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("uppercase fallback: %d %s, want 422", code, body)
	}

	// An explicit "block" resets the stored policy.
	code, body = itReq(t, srv, "PUT", "/api/v1/tenants/acme/git-config", "good",
		`{"repo":"acme/acme-inari-state","commitPolicy":"direct","userTemplateFallback":"block"}`)
	if code != http.StatusOK && code != http.StatusNoContent {
		t.Fatalf("explicit block: %d %s", code, body)
	}
	cfg, err = inv.GitConfig(ctx, database.Pool, "org:1")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UserTemplateFallback != "block" {
		t.Fatalf("fallback = %q, want block", cfg.UserTemplateFallback)
	}
}
