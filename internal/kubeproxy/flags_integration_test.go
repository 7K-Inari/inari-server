//go:build integration

package kubeproxy

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/open-feature/go-sdk/openfeature"

	tunnelv2 "github.com/7K-Inari/inari-api/gen/go/inari/tunnel/v2"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/featureflags"
)

// itRuntimeFlags wires the real kill-switch v2 read path (OpenFeature client
// over the DB provider) against the test database. No cache: every read hits
// Postgres, so writes are visible immediately.
func itRuntimeFlags(t *testing.T, database *db.DB) (*featureflags.Resolver, *featureflags.Service) {
	t.Helper()
	store := featureflags.NewStore()
	domain := t.Name()
	if err := openfeature.SetNamedProviderAndWait(domain,
		featureflags.NewDBProvider(database.Pool, store, nil, "memory", time.Minute)); err != nil {
		t.Fatal(err)
	}
	resolver := featureflags.NewResolver(openfeature.NewClient(domain), nil)
	svc := featureflags.NewService(database, store, audit.NewStore(), nil, "memory")
	return resolver, svc
}

func itGet(t *testing.T, srvURL, clusterID string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, srvURL+"/api/v1/tenants/acme/clusters/"+clusterID+"/proxy/api", nil)
	req.Header.Set("Authorization", "Bearer good")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

// TestProxyRuntimeFlagClusterScoped proves the DB-backed flag gates the
// proxy per cluster: disabling clu-1 410s only clu-1; re-enabling restores.
func TestProxyRuntimeFlagClusterScoped(t *testing.T) {
	database := setupInfra(t)
	resolver, svc := itRuntimeFlags(t, database)
	srv, _ := startProxy(t, database, withFlags(resolver))
	ctx := context.Background()

	// No rows: requests pass the flag gate and hit the no-tunnel 503.
	if code := itGet(t, srv.URL, "c1"); code != http.StatusServiceUnavailable {
		t.Fatalf("default: status = %d, want 503 (no tunnel)", code)
	}
	if err := svc.Set(ctx, "op", "org:1", featureflags.KeyKubectlAccessEnabled, featureflags.ScopeCluster, "c1", false); err != nil {
		t.Fatal(err)
	}
	if code := itGet(t, srv.URL, "c1"); code != http.StatusGone {
		t.Fatalf("cluster disabled: status = %d, want 410", code)
	}
	if code := itGet(t, srv.URL, "c2"); code != http.StatusServiceUnavailable {
		t.Fatalf("other cluster unaffected: status = %d, want 503 (no tunnel)", code)
	}
	if err := svc.Clear(ctx, "op", "org:1", featureflags.KeyKubectlAccessEnabled, featureflags.ScopeCluster, "c1"); err != nil {
		t.Fatal(err)
	}
	if code := itGet(t, srv.URL, "c1"); code != http.StatusServiceUnavailable {
		t.Fatalf("re-enabled: status = %d, want 503 (no tunnel)", code)
	}
}

// TestProxyRuntimeFlagPlatform proves the platform-scope row gates all
// clusters, and that an env override beats runtime state.
func TestProxyRuntimeFlagPlatform(t *testing.T) {
	database := setupInfra(t)
	resolver, svc := itRuntimeFlags(t, database)
	srv, _ := startProxy(t, database, withFlags(resolver))
	ctx := context.Background()

	if err := svc.Set(ctx, "admin", "", featureflags.KeyKubectlAccessEnabled, featureflags.ScopePlatform, "", false); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"c1", "c2"} {
		if code := itGet(t, srv.URL, id); code != http.StatusGone {
			t.Fatalf("platform disabled: %s status = %d, want 410", id, code)
		}
	}

	// Env explicitly SET true overrides the runtime false (hard precedence
	// rule): the resolver pins the flag before the provider is consulted.
	pinned := featureflags.NewResolver(openfeature.NewClient(t.Name()), map[string]bool{featureflags.KeyKubectlAccessEnabled: true})
	srv2, _ := startProxy(t, database, withFlags(pinned))
	if code := itGet(t, srv2.URL, "c1"); code != http.StatusServiceUnavailable {
		t.Fatalf("env override must beat runtime false: status = %d, want 503 (no tunnel)", code)
	}
}

// TestFlagWatcherClosesLiveSessionOnFlip proves a runtime flip to off closes
// a session that connected while the flag was on (per-cluster blast radius).
func TestFlagWatcherClosesLiveSessionOnFlip(t *testing.T) {
	database := setupInfra(t)
	resolver, svc := itRuntimeFlags(t, database)
	sessions := NewSessionRegistry()
	live := newSession(context.Background(), "c1", func(*tunnelv2.TunnelMessage) error { return nil }, 0)
	sessions.Register(live)

	w := NewFlagWatcher(resolver, sessions)
	ctx := context.Background()
	w.tick(ctx)
	if sessions.Get("c1") == nil {
		t.Fatal("session closed while the flag is on")
	}
	if err := svc.Set(ctx, "op", "org:1", featureflags.KeyKubectlAccessEnabled, featureflags.ScopeCluster, "c1", false); err != nil {
		t.Fatal(err)
	}
	w.tick(ctx)
	if sessions.Get("c1") != nil {
		t.Error("session still live after cluster flag flip to off")
	}
	select {
	case <-live.done:
	case <-time.After(time.Second):
		t.Error("session not closed after cluster flag flip to off")
	}
}
