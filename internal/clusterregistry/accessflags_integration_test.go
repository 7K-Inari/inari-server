//go:build integration

package clusterregistry

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-feature/go-sdk/openfeature"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/featureflags"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
	"github.com/7K-Inari/inari-server/internal/types"
)

// TestAccessInfoRuntimeFlagPerCluster proves access-info reports the
// per-cluster effective flag value (kill-switch v2 split-brain fix): one
// disabled cluster reports disabled while a sibling reports enabled, and the
// kubeconfig endpoint 410s only for the disabled cluster.
func TestAccessInfoRuntimeFlagPerCluster(t *testing.T) {
	ctx := context.Background()
	pg, err := testutil.SharedPostgres(ctx)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	database, err := testdb.NewDatabase(t, pg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx,
		`INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES
		 ('org:1','acme','Acme','kc-1'), ('org:2','acme2','Acme2','kc-2')`); err != nil {
		t.Fatal(err)
	}

	flagStore := featureflags.NewStore()
	if err := openfeature.SetNamedProviderAndWait(t.Name(),
		featureflags.NewDBProvider(database.Pool, flagStore, nil, "memory", time.Minute)); err != nil {
		t.Fatal(err)
	}
	resolver := featureflags.NewResolver(openfeature.NewClient(t.Name()), nil)
	flagSvc := featureflags.NewService(database, flagStore, audit.NewStore(), nil, "memory")

	svc := NewService(database, itClients{}, NewStore(), audit.NewStore(), time.Hour, false)
	h := NewHandler(svc, itTenants{
		"acme":  {ID: "org:1", Slug: "acme"},
		"acme2": {ID: "org:2", Slug: "acme2"},
	}, itAuthorizer{allow: true}, nil).
		WithAccessInfo("https://keycloak.example.com/realms/inari").
		WithKubectlGateway("https://proxy.example.com", resolver, nil)
	router, api := httpserver.NewRouter(slog.Default(), itValidator{}, database)
	h.RegisterRoutes(api)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	idOff := itCreate(t, srv, "acme", "prod-off")
	idOn := itCreate(t, srv, "acme", "prod-on")

	accessInfo := func(id string) types.ClusterAccessInfo {
		t.Helper()
		code, body := itReq(t, srv, "GET", "/api/v1/tenants/acme/clusters/"+id+"/access-info", "good", "")
		if code != 200 {
			t.Fatalf("access-info: %d %s", code, body)
		}
		var out struct {
			AccessInfo types.ClusterAccessInfo `json:"accessInfo"`
		}
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatal(err)
		}
		return out.AccessInfo
	}
	if !accessInfo(idOff).KubectlAccessEnabled || !accessInfo(idOn).KubectlAccessEnabled {
		t.Fatal("default: both clusters must report enabled")
	}

	if err := flagSvc.Set(ctx, "op", "org:1", featureflags.KeyKubectlAccessEnabled, featureflags.ScopeCluster, idOff, false); err != nil {
		t.Fatal(err)
	}
	ai := accessInfo(idOff)
	if ai.KubectlAccessEnabled {
		t.Error("disabled cluster still reports enabled")
	}
	if !strings.Contains(ai.TunnelUnavailableReason, "disabled by platform policy") {
		t.Errorf("tunnelUnavailableReason = %q", ai.TunnelUnavailableReason)
	}
	if !accessInfo(idOn).KubectlAccessEnabled {
		t.Error("sibling cluster must stay enabled (blast-radius isolation)")
	}

	code, body := itReq(t, srv, "GET", "/api/v1/tenants/acme/clusters/"+idOff+"/kubeconfig", "good", "")
	if code != 410 {
		t.Errorf("kubeconfig for disabled cluster: %d %s, want 410", code, body)
	}
	code, _ = itReq(t, srv, "GET", "/api/v1/tenants/acme/clusters/"+idOn+"/kubeconfig", "good", "")
	if code != 200 {
		t.Errorf("kubeconfig for enabled cluster: %d, want 200", code)
	}

	// Re-enable without any restart.
	if err := flagSvc.Clear(ctx, "op", "org:1", featureflags.KeyKubectlAccessEnabled, featureflags.ScopeCluster, idOff); err != nil {
		t.Fatal(err)
	}
	if !accessInfo(idOff).KubectlAccessEnabled {
		t.Error("cleared override must restore enabled")
	}
}
