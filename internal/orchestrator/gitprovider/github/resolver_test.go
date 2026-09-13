package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// fakeGitHub serves App-level + installation-level endpoints for resolver tests.
type fakeGitHub struct {
	listCalls     atomic.Int32
	tokenCalls    sync.Map // installationID -> *atomic.Int32
	installations []map[string]any
	pages         int // >0: split installations across N pages
	failData      atomic.Bool
	probeStatus   atomic.Int32 // force status on /installation/repositories
	repoSelection string
	repoNames     []string
}

func (f *fakeGitHub) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v3/app/installations" || r.URL.Path == "/app/installations" ||
			(strings.HasPrefix(r.URL.Path, "/api/v3/") && strings.HasSuffix(r.URL.Path, "/app/installations")) {
			f.listCalls.Add(1)
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			page := 1
			if p := r.URL.Query().Get("page"); p != "" {
				fmt.Sscanf(p, "%d", &page)
			}
			items := f.installations
			perPage := 100
			if f.pages > 1 {
				perPage = (len(items) + f.pages - 1) / f.pages
			}
			start := (page - 1) * perPage
			end := start + perPage
			if start > len(items) {
				start = len(items)
			}
			if end > len(items) {
				end = len(items)
			}
			if end < len(items) {
				w.Header().Set("Link", fmt.Sprintf(`<?page=%d&per_page=%d>; rel="next"`, page+1, perPage))
			}
			_ = json.NewEncoder(w).Encode(items[start:end])
			return
		}
		// single installation lookup (legacy seed)
		for _, inst := range f.installations {
			id := inst["id"].(int64)
			if r.URL.Path == fmt.Sprintf("/app/installations/%d", id) {
				_ = json.NewEncoder(w).Encode(inst)
				return
			}
			if r.URL.Path == fmt.Sprintf("/app/installations/%d/access_tokens", id) ||
				r.URL.Path == fmt.Sprintf("/api/v3/app/installations/%d/access_tokens", id) {
				cnt, _ := f.tokenCalls.LoadOrStore(id, &atomic.Int32{})
				cnt.(*atomic.Int32).Add(1)
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"token": fmt.Sprintf("tok-%d", id), "expires_at": "2099-01-01T00:00:00Z",
				})
				return
			}
			if strings.HasSuffix(r.URL.Path, "/installation/repositories") {
				if r.Header.Get("Authorization") != fmt.Sprintf("Bearer tok-%d", id) {
					continue
				}
				if s := f.probeStatus.Load(); s != 0 {
					w.WriteHeader(int(s))
					return
				}
				sel := f.repoSelection
				if sel == "" {
					sel = "selected"
				}
				names := f.repoNames
				if names == nil {
					names = []string{"acme-inari-state"}
				}
				repos := []map[string]any{}
				for _, n := range names {
					repos = append(repos, map[string]any{"name": n})
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"repository_selection": sel, "repositories": repos})
				return
			}
		}
		// data routes: require the installation token matching the URL owner
		for _, inst := range f.installations {
			id := inst["id"].(int64)
			login := strings.ToLower(inst["account"].(map[string]any)["login"].(string))
			if strings.HasPrefix(r.URL.Path, "/repos/"+login+"/") {
				if r.Header.Get("Authorization") != fmt.Sprintf("Bearer tok-%d", id) {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				if f.failData.Load() {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"name": "ok"})
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	})
}

func inst(id int64, login string) map[string]any {
	return map[string]any{"id": id, "account": map[string]any{"login": login}}
}

func writePlatformKey(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	f := filepath.Join(t.TempDir(), "platform.pem")
	if err := os.WriteFile(f, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return f, key
}

func newTestResolver(t *testing.T, gh *fakeGitHub, mutate func(*ResolverConfig)) (*Resolver, *httptest.Server) {
	t.Helper()
	keyFile, _ := writePlatformKey(t)
	srv := httptest.NewServer(gh.handler())
	t.Cleanup(srv.Close)
	cfg := ResolverConfig{
		PlatformAppID:          10,
		PlatformPrivateKeyFile: keyFile,
		PlatformAPIBase:        srv.URL,
		PlatformAppSlug:        "inari-platform",
	}
	if mutate != nil {
		mutate(&cfg)
	}
	r, err := NewResolver(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r, srv
}

func gitCfg(orgID, repo string) *types.TenantGitConfig {
	return &types.TenantGitConfig{OrgID: orgID, Repo: repo, CommitPolicy: types.CommitPolicyDirect, BaseBranch: "main"}
}

func TestResolverDiscoversInstallationPerTenant(t *testing.T) {
	gh := &fakeGitHub{installations: []map[string]any{inst(2, "acme"), inst(3, "globex")}}
	r, _ := newTestResolver(t, gh, nil)
	ctx := context.Background()

	p1, info1, err := r.ForTenant(ctx, gitCfg("org:1", "acme/acme-inari-state"))
	if err != nil {
		t.Fatal(err)
	}
	if info1.Model != gitprovider.AuthModelPlatform || info1.InstallationID != 2 {
		t.Errorf("info = %+v", info1)
	}
	p2, info2, err := r.ForTenant(ctx, gitCfg("org:2", "globex/globex-inari-state"))
	if err != nil {
		t.Fatal(err)
	}
	if info2.InstallationID != 3 {
		t.Errorf("info = %+v", info2)
	}
	if p1 == p2 {
		t.Error("tenants must get distinct providers")
	}
	// One list call warms the cache for all orgs.
	if n := gh.listCalls.Load(); n != 1 {
		t.Errorf("list calls = %d, want 1", n)
	}
	// The provider talks to GitHub with its own installation token.
	if _, err := p1.EnsureRepo(ctx, "acme/acme-inari-state"); err != nil {
		t.Fatal(err)
	}
}

func TestResolverCacheTTLExpiry(t *testing.T) {
	gh := &fakeGitHub{installations: []map[string]any{inst(2, "acme")}}
	now := time.Now()
	r, _ := newTestResolver(t, gh, func(c *ResolverConfig) {
		c.CacheTTL = time.Minute
		c.Now = func() time.Time { return now }
	})
	ctx := context.Background()
	if _, _, err := r.ForTenant(ctx, gitCfg("org:1", "acme/acme-inari-state")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.ForTenant(ctx, gitCfg("org:1", "acme/acme-inari-state")); err != nil {
		t.Fatal(err)
	}
	if n := gh.listCalls.Load(); n != 1 {
		t.Fatalf("list calls = %d, want 1", n)
	}
	now = now.Add(2 * time.Minute)
	if _, _, err := r.ForTenant(ctx, gitCfg("org:1", "acme/acme-inari-state")); err != nil {
		t.Fatal(err)
	}
	if n := gh.listCalls.Load(); n != 2 {
		t.Errorf("list calls = %d after TTL expiry, want 2", n)
	}
}

func TestResolverNotInstalledTypedError(t *testing.T) {
	gh := &fakeGitHub{installations: []map[string]any{inst(2, "acme")}}
	r, srv := newTestResolver(t, gh, nil)
	ctx := context.Background()
	_, _, err := r.ForTenant(ctx, gitCfg("org:9", "missing/missing-inari-state"))
	var ni *ErrAppNotInstalled
	if !errors.As(err, &ni) {
		t.Fatalf("err = %v (%T), want ErrAppNotInstalled", err, err)
	}
	wantURL := srv.URL + "/apps/inari-platform/installations/new"
	if ni.InstallURL != wantURL {
		t.Errorf("InstallURL = %q, want %q", ni.InstallURL, wantURL)
	}
	// Negative cache: a second resolution within the negative TTL must not re-list.
	_, _, _ = r.ForTenant(ctx, gitCfg("org:9", "missing/missing-inari-state"))
	if n := gh.listCalls.Load(); n != 1 {
		t.Errorf("list calls = %d, want 1 (negative cache)", n)
	}
}

func TestResolverLegacyInstallationSeed(t *testing.T) {
	gh := &fakeGitHub{installations: []map[string]any{inst(2, "acme")}}
	r, _ := newTestResolver(t, gh, func(c *ResolverConfig) { c.LegacyInstallationID = 2 })
	ctx := context.Background()
	_, info, err := r.ForTenant(ctx, gitCfg("org:1", "acme/acme-inari-state"))
	if err != nil {
		t.Fatal(err)
	}
	if info.InstallationID != 2 {
		t.Errorf("installation = %d", info.InstallationID)
	}
	if n := gh.listCalls.Load(); n != 0 {
		t.Errorf("list calls = %d, want 0 (legacy seed)", n)
	}
}

func TestResolverPaginatesInstallations(t *testing.T) {
	gh := &fakeGitHub{
		installations: []map[string]any{inst(2, "acme"), inst(3, "globex"), inst(4, "initech")},
		pages:         3,
	}
	r, _ := newTestResolver(t, gh, nil)
	_, info, err := r.ForTenant(context.Background(), gitCfg("org:3", "initech/initech-inari-state"))
	if err != nil {
		t.Fatal(err)
	}
	if info.InstallationID != 4 {
		t.Errorf("installation = %d, want 4 (found on page 3)", info.InstallationID)
	}
	if n := gh.listCalls.Load(); n != 3 {
		t.Errorf("list calls = %d, want 3 pages", n)
	}
}

func TestResolver401InvalidatesAndReResolves(t *testing.T) {
	gh := &fakeGitHub{installations: []map[string]any{inst(2, "acme")}}
	r, _ := newTestResolver(t, gh, nil)
	ctx := context.Background()
	p, _, err := r.ForTenant(ctx, gitCfg("org:1", "acme/acme-inari-state"))
	if err != nil {
		t.Fatal(err)
	}
	// Suspend the app: data ops start failing with 401.
	gh.failData.Store(true)
	_, err = p.EnsureRepo(ctx, "acme/acme-inari-state")
	var revoked *ErrAppCredentialsRevoked
	if !errors.As(err, &revoked) {
		t.Fatalf("err = %v (%T), want ErrAppCredentialsRevoked", err, err)
	}
	// Cache was invalidated: next resolution re-lists (fresh state on reinstall).
	gh.failData.Store(false)
	if _, _, err := r.ForTenant(ctx, gitCfg("org:1", "acme/acme-inari-state")); err != nil {
		t.Fatal(err)
	}
	if n := gh.listCalls.Load(); n != 2 {
		t.Errorf("list calls = %d, want 2 (re-resolved after invalidation)", n)
	}
}

func TestResolverBYOOverridesPlatform(t *testing.T) {
	gh := &fakeGitHub{installations: []map[string]any{inst(2, "acme")}}
	_, byoKey := writePlatformKey(t)
	var loads atomic.Int32
	r, srv := newTestResolver(t, gh, func(c *ResolverConfig) {
		c.KeyLoader = func(_ context.Context, ref *types.GitHubAppSecretRef) (*rsa.PrivateKey, error) {
			loads.Add(1)
			if ref.SecretName != "byo-key" {
				return nil, fmt.Errorf("unknown secret %q", ref.SecretName)
			}
			return byoKey, nil
		}
	})
	cfg := gitCfg("org:1", "acme/acme-inari-state")
	cfg.GitHubApp = &types.GitHubAppConfig{
		AppID:          99,
		InstallationID: 2,
		APIBase:        srv.URL,
		KeyRef:         &types.GitHubAppSecretRef{SecretName: "byo-key", Namespace: "ns", Key: "k"},
	}
	ctx := context.Background()
	_, info, err := r.ForTenant(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if info.Model != gitprovider.AuthModelBYO || info.AppID != 99 || info.InstallationID != 2 {
		t.Errorf("info = %+v", info)
	}
	if n := gh.listCalls.Load(); n != 0 {
		t.Errorf("list calls = %d, want 0 (BYO skips platform discovery)", n)
	}
	// Cached: second call does not reload the key.
	if _, _, err := r.ForTenant(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if n := loads.Load(); n != 1 {
		t.Errorf("key loads = %d, want 1 (cached)", n)
	}
}

func TestResolverBYORotationOn401(t *testing.T) {
	gh := &fakeGitHub{installations: []map[string]any{inst(2, "acme")}}
	_, key1 := writePlatformKey(t)
	_, key2 := writePlatformKey(t)
	current := key1
	var loads atomic.Int32
	r, srv := newTestResolver(t, gh, func(c *ResolverConfig) {
		c.KeyLoader = func(_ context.Context, _ *types.GitHubAppSecretRef) (*rsa.PrivateKey, error) {
			loads.Add(1)
			return current, nil
		}
	})
	cfg := gitCfg("org:1", "acme/acme-inari-state")
	cfg.GitHubApp = &types.GitHubAppConfig{
		AppID: 99, InstallationID: 2, APIBase: srv.URL,
		KeyRef: &types.GitHubAppSecretRef{SecretName: "byo-key", Namespace: "ns", Key: "k"},
	}
	ctx := context.Background()
	p, _, err := r.ForTenant(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Suspend: 401 → provider evicted (rotation pickup on next resolve).
	gh.failData.Store(true)
	if _, err := p.EnsureRepo(ctx, "acme/acme-inari-state"); err == nil {
		t.Fatal("want error on 401")
	}
	// Rotate the key (ESO re-render) + reinstall the app.
	current = key2
	gh.failData.Store(false)
	p2, _, err := r.ForTenant(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p2.EnsureRepo(ctx, "acme/acme-inari-state"); err != nil {
		t.Fatal(err)
	}
	if n := loads.Load(); n != 2 {
		t.Errorf("key loads = %d, want 2 (reloaded after eviction)", n)
	}
}

func TestResolverEvictTenant(t *testing.T) {
	gh := &fakeGitHub{installations: []map[string]any{inst(2, "acme")}}
	_, byoKey := writePlatformKey(t)
	var loads atomic.Int32
	r, srv := newTestResolver(t, gh, func(c *ResolverConfig) {
		c.KeyLoader = func(_ context.Context, _ *types.GitHubAppSecretRef) (*rsa.PrivateKey, error) {
			loads.Add(1)
			return byoKey, nil
		}
	})
	cfg := gitCfg("org:1", "acme/acme-inari-state")
	cfg.GitHubApp = &types.GitHubAppConfig{
		AppID: 99, InstallationID: 2, APIBase: srv.URL,
		KeyRef: &types.GitHubAppSecretRef{SecretName: "byo-key", Namespace: "ns", Key: "k"},
	}
	ctx := context.Background()
	if _, _, err := r.ForTenant(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	r.EvictTenant("org:1")
	if _, _, err := r.ForTenant(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if n := loads.Load(); n != 2 {
		t.Errorf("key loads = %d, want 2 after EvictTenant", n)
	}
}

func TestResolverGHEBaseSeparation(t *testing.T) {
	// Platform app on github.com-shaped base; BYO tenant on a GHE host.
	ghCloud := &fakeGitHub{installations: []map[string]any{inst(2, "acme")}}
	ghGHE := &fakeGitHub{installations: []map[string]any{inst(7, "globex")}}
	keyFile, _ := writePlatformKey(t)
	_, byoKey := writePlatformKey(t)
	cloudSrv := httptest.NewServer(ghCloud.handler())
	t.Cleanup(cloudSrv.Close)
	gheSrv := httptest.NewServer(http.StripPrefix("/api/v3", ghGHE.handler()))
	t.Cleanup(gheSrv.Close)

	r, err := NewResolver(ResolverConfig{
		PlatformAppID:          10,
		PlatformPrivateKeyFile: keyFile,
		PlatformAPIBase:        cloudSrv.URL,
		PlatformAppSlug:        "inari-platform",
		KeyLoader: func(_ context.Context, _ *types.GitHubAppSecretRef) (*rsa.PrivateKey, error) {
			return byoKey, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	byo := gitCfg("org:2", "globex/globex-inari-state")
	byo.GitHubApp = &types.GitHubAppConfig{
		AppID: 55, InstallationID: 7, APIBase: gheSrv.URL + "/api/v3",
		KeyRef: &types.GitHubAppSecretRef{SecretName: "k", Namespace: "ns", Key: "k"},
	}
	pGHE, infoGHE, err := r.ForTenant(ctx, byo)
	if err != nil {
		t.Fatal(err)
	}
	pCloud, infoCloud, err := r.ForTenant(ctx, gitCfg("org:1", "acme/acme-inari-state"))
	if err != nil {
		t.Fatal(err)
	}
	if infoGHE.APIBase != gheSrv.URL+"/api/v3" || infoCloud.APIBase != cloudSrv.URL {
		t.Errorf("api bases leaked: byo=%q platform=%q", infoGHE.APIBase, infoCloud.APIBase)
	}
	// Clone URLs derive from each provider's own base.
	urlGHE, err := pGHE.EnsureRepo(ctx, "globex/globex-inari-state")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(urlGHE, gheSrv.URL+"/") {
		t.Errorf("GHE clone url = %q", urlGHE)
	}
	urlCloud, err := pCloud.EnsureRepo(ctx, "acme/acme-inari-state")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(urlCloud, cloudSrv.URL+"/") {
		t.Errorf("cloud clone url = %q", urlCloud)
	}
}

func TestResolverScopeWarningEvent(t *testing.T) {
	gh := &fakeGitHub{
		installations: []map[string]any{inst(2, "acme")},
		repoSelection: "all",
	}
	var events []ResolvedEvent
	r, _ := newTestResolver(t, gh, func(c *ResolverConfig) {
		c.OnResolved = func(_ context.Context, ev ResolvedEvent) { events = append(events, ev) }
	})
	if _, _, err := r.ForTenant(context.Background(), gitCfg("org:1", "acme/acme-inari-state")); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, ev := range events {
		if ev.Result == "scope_warning" {
			found = true
		}
	}
	if !found {
		t.Errorf("events = %+v, want a scope_warning", events)
	}
}

func TestResolverBYOWithoutLoader(t *testing.T) {
	gh := &fakeGitHub{installations: []map[string]any{inst(2, "acme")}}
	r, _ := newTestResolver(t, gh, nil)
	cfg := gitCfg("org:1", "acme/acme-inari-state")
	cfg.GitHubApp = &types.GitHubAppConfig{AppID: 1, InstallationID: 2,
		KeyRef: &types.GitHubAppSecretRef{SecretName: "s", Namespace: "n", Key: "k"}}
	if _, _, err := r.ForTenant(context.Background(), cfg); err == nil {
		t.Fatal("want error when KeyLoader is not configured")
	}
}

func TestProbeStates(t *testing.T) {
	gh := &fakeGitHub{installations: []map[string]any{inst(2, "acme")}}
	r, _ := newTestResolver(t, gh, nil)
	ctx := context.Background()

	st := r.Probe(ctx, gitCfg("org:1", "acme/acme-inari-state"))
	if st.State != "ok" || st.AuthModel != "platform" || st.InstallationID != 2 {
		t.Errorf("probe = %+v", st)
	}

	st = r.Probe(ctx, gitCfg("org:9", "missing/missing-inari-state"))
	if st.State != "not_installed" {
		t.Errorf("probe = %+v, want not_installed", st)
	}

	gh.probeStatus.Store(401)
	st = r.Probe(ctx, gitCfg("org:2", "acme/acme-inari-state"))
	if st.State != "invalid_credentials" {
		t.Errorf("probe = %+v, want invalid_credentials", st)
	}

	gh.probeStatus.Store(429)
	st = r.Probe(ctx, gitCfg("org:3", "acme/acme-inari-state"))
	if st.State != "rate_limited" {
		t.Errorf("probe = %+v, want rate_limited", st)
	}
}

func TestProbeCached(t *testing.T) {
	gh := &fakeGitHub{installations: []map[string]any{inst(2, "acme")}}
	now := time.Now()
	var probes atomic.Int32
	r, _ := newTestResolver(t, gh, func(c *ResolverConfig) {
		c.Now = func() time.Time { return now }
	})
	_ = probes
	ctx := context.Background()
	cfg := gitCfg("org:1", "acme/acme-inari-state")
	st1 := r.Probe(ctx, cfg)
	// Force an error state; a cached probe must still return the old result.
	gh.probeStatus.Store(500)
	st2 := r.Probe(ctx, cfg)
	if st2.State != st1.State {
		t.Errorf("probe not cached: %q then %q", st1.State, st2.State)
	}
	now = now.Add(2 * time.Minute)
	st3 := r.Probe(ctx, cfg)
	if st3.State != "unknown" {
		t.Errorf("probe after cache expiry = %q, want unknown", st3.State)
	}
}
