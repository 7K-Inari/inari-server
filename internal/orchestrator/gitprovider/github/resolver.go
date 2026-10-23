package github

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/sync/singleflight"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// KeyLoader loads a tenant's BYO GitHub App private key from an ESO-mounted
// secret reference (the key bytes never touch the DB, ADR-0004).
type KeyLoader func(ctx context.Context, ref *types.GitHubAppSecretRef) (*rsa.PrivateKey, error)

// ResolvedEvent reports a credential resolution (cache miss/refresh/failure)
// for audit; never emitted on cache hits.
type ResolvedEvent struct {
	OrgID          string
	AuthModel      gitprovider.AuthModel
	AppID          int64
	InstallationID int64
	APIBase        string
	Result         string // resolved|scope_warning|not_installed|not_connected|error
	// Model C fields (empty for platform/BYO).
	UserSub      string
	ConnectionID string
}

// ResolverConfig configures the hybrid per-tenant git provider resolver.
type ResolverConfig struct {
	PlatformAppID          int64
	PlatformPrivateKeyFile string // ESO-mounted PEM
	// PlatformAPIBase is the platform app's API base: "" →
	// https://api.github.com, or a GHE https://<host>/api/v3.
	PlatformAPIBase string
	// PlatformAppSlug builds install links (<web>/apps/<slug>/installations/new).
	PlatformAppSlug string
	// LegacyInstallationID (deprecated INARI_GITHUB_APP_INSTALLATION_ID)
	// seeds the installation cache for its org — back-compat default.
	LegacyInstallationID int64
	// KeyLoader enables model B (BYO app per tenant); nil disables it.
	KeyLoader KeyLoader
	// CacheTTL for installation discovery (default 5m).
	CacheTTL time.Duration
	// NegativeTTL for "org has no installation" (default 30s).
	NegativeTTL time.Duration
	// Now is a test hook for cache ageing.
	Now func() time.Time
	// OnResolved is invoked on resolution events (audit hook).
	OnResolved func(ctx context.Context, ev ResolvedEvent)
}

// ErrAppNotInstalled: the (platform or BYO) app has no installation on the
// tenant's state-repo org. InstallURL guides the tenant admin.
type ErrAppNotInstalled struct {
	Org        string
	InstallURL string
}

func (e *ErrAppNotInstalled) Error() string {
	return fmt.Sprintf("gitprovider github: app not installed on org %q; install it (scoped to the *-inari-state repo only): %s", e.Org, e.InstallURL)
}

// ErrAppCredentialsRevoked: the app's credentials were suspended, revoked,
// or its installation deleted mid-flight.
type ErrAppCredentialsRevoked struct {
	OrgID          string
	AppID          int64
	InstallationID int64
	APIBase        string
}

func (e *ErrAppCredentialsRevoked) Error() string {
	return fmt.Sprintf("gitprovider github: credentials revoked/suspended for app %d installation %d (tenant %s, api %s)",
		e.AppID, e.InstallationID, e.OrgID, e.APIBase)
}

type installation struct {
	id        int64
	fetchedAt time.Time
	notFound  bool
}

type cachedProvider struct {
	provider gitprovider.Provider
	info     *gitprovider.AuthInfo
	owner    string // account login (model A) for invalidation
}

type statusEntry struct {
	status    *types.GitProviderStatus
	checkedAt time.Time
}

// Resolver resolves a gitprovider.Provider per tenant: BYO app override
// (model B) when configured, else the platform app with a per-org
// installation discovered at runtime (model A).
type Resolver struct {
	// User is the optional model-C (per-user OAuth) resolver; nil disables
	// user resolution (ForUser fails closed).
	User        *UserResolver
	cfg         ResolverConfig
	platformKey *rsa.PrivateKey
	apiBase     string
	http        *http.Client
	now         func() time.Time

	mu        sync.Mutex
	installs  map[string]installation // key: lower(account.login)
	providers map[string]*cachedProvider
	status    map[string]statusEntry

	legacySeeded bool // true only after a successful seed (retries on failure)
	sf           singleflight.Group
}

// NewResolver parses the platform app key and prepares caches. The legacy
// installation seed resolves lazily on first use (no startup network call).
func NewResolver(cfg ResolverConfig) (*Resolver, error) {
	raw, err := os.ReadFile(cfg.PlatformPrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("gitprovider github resolver: read platform key: %w", err)
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(raw)
	if err != nil {
		return nil, fmt.Errorf("gitprovider github resolver: parse platform key: %w", err)
	}
	base := cfg.PlatformAPIBase
	if base == "" {
		base = "https://api.github.com"
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Resolver{
		cfg:         cfg,
		platformKey: key,
		apiBase:     strings.TrimSuffix(base, "/"),
		http:        &http.Client{Timeout: 30 * time.Second},
		now:         now,
		installs:    map[string]installation{},
		providers:   map[string]*cachedProvider{},
		status:      map[string]statusEntry{},
	}, nil
}

func (r *Resolver) cacheTTL() time.Duration {
	if r.cfg.CacheTTL > 0 {
		return r.cfg.CacheTTL
	}
	return 5 * time.Minute
}

func (r *Resolver) negativeTTL() time.Duration {
	if r.cfg.NegativeTTL > 0 {
		return r.cfg.NegativeTTL
	}
	return 30 * time.Second
}

func (r *Resolver) emit(ctx context.Context, ev ResolvedEvent) {
	if r.cfg.OnResolved != nil {
		r.cfg.OnResolved(ctx, ev)
	}
}

// ForTenant resolves the provider for one tenant's git config.
func (r *Resolver) ForTenant(ctx context.Context, cfg *types.TenantGitConfig) (gitprovider.Provider, *gitprovider.AuthInfo, error) {
	if cfg.GitHubApp != nil {
		return r.forTenantBYO(ctx, cfg)
	}
	return r.forTenantPlatform(ctx, cfg)
}

// ForUser implements gitprovider.Resolver for model C, delegating to the
// wired UserResolver. Fails closed when user resolution is not wired.
func (r *Resolver) ForUser(ctx context.Context, orgID, userSub string) (gitprovider.Provider, *gitprovider.AuthInfo, error) {
	if r.User == nil {
		return nil, nil, gitprovider.ErrUserModelUnsupported
	}
	return r.User.ForUser(ctx, orgID, userSub)
}

// forTenantPlatform implements model A: platform app + per-org installation.
func (r *Resolver) forTenantPlatform(ctx context.Context, cfg *types.TenantGitConfig) (gitprovider.Provider, *gitprovider.AuthInfo, error) {
	owner, _, err := splitRepo(cfg.Repo)
	if err != nil {
		return nil, nil, err
	}
	login := strings.ToLower(owner)
	r.seedLegacy(ctx)

	r.mu.Lock()
	inst, ok := r.installs[login]
	r.mu.Unlock()
	ttl := r.cacheTTL()
	if ok && inst.notFound {
		ttl = r.negativeTTL()
	}
	if ok && r.now().Sub(inst.fetchedAt) < ttl {
		if inst.notFound {
			return nil, nil, r.notInstalledErr(owner)
		}
		return r.platformProvider(ctx, cfg.OrgID, owner, cfg.Repo, inst.id)
	}

	// Cold/stale: rediscover (single-flight per org).
	_, err, _ = r.sf.Do(login, func() (any, error) {
		return nil, r.discover(ctx)
	})
	if err != nil {
		r.emit(ctx, ResolvedEvent{OrgID: cfg.OrgID, AuthModel: gitprovider.AuthModelPlatform, AppID: r.cfg.PlatformAppID, APIBase: r.apiBase, Result: "error"})
		return nil, nil, err
	}
	r.mu.Lock()
	inst, ok = r.installs[login]
	r.mu.Unlock()
	if !ok {
		r.noteNotFound(login)
	}
	if !ok || inst.notFound {
		r.emit(ctx, ResolvedEvent{OrgID: cfg.OrgID, AuthModel: gitprovider.AuthModelPlatform, AppID: r.cfg.PlatformAppID, APIBase: r.apiBase, Result: "not_installed"})
		return nil, nil, r.notInstalledErr(owner)
	}
	return r.platformProvider(ctx, cfg.OrgID, owner, cfg.Repo, inst.id)
}

func (r *Resolver) notInstalledErr(org string) *ErrAppNotInstalled {
	return &ErrAppNotInstalled{Org: org, InstallURL: webBaseFrom(r.apiBase) + "/apps/" + r.cfg.PlatformAppSlug + "/installations/new"}
}

// platformProvider returns the cached provider for one installation.
func (r *Resolver) platformProvider(ctx context.Context, orgID, owner, repo string, installationID int64) (gitprovider.Provider, *gitprovider.AuthInfo, error) {
	key := fmt.Sprintf("i:%d", installationID)
	r.mu.Lock()
	cp, ok := r.providers[key]
	r.mu.Unlock()
	if ok {
		return cp.provider, cp.info, nil
	}
	info := &gitprovider.AuthInfo{
		Model: gitprovider.AuthModelPlatform, AppID: r.cfg.PlatformAppID,
		InstallationID: installationID, APIBase: r.apiBase,
	}
	inner := NewWithKey(r.cfg.PlatformAppID, installationID, r.platformKey, r.apiBase)
	wrapped := r.wrapPlatform(inner, orgID, owner, info)
	r.mu.Lock()
	r.providers[key] = &cachedProvider{provider: wrapped, info: info, owner: owner}
	r.mu.Unlock()
	r.emit(ctx, ResolvedEvent{OrgID: orgID, AuthModel: info.Model, AppID: info.AppID, InstallationID: installationID, APIBase: r.apiBase, Result: "resolved"})
	r.scopeCheck(ctx, inner, orgID, repo, info)
	return wrapped, info, nil
}

// wrapPlatform maps installation-level API failures to typed errors and
// invalidates the installation cache (model A).
func (r *Resolver) wrapPlatform(inner *Provider, orgID, owner string, info *gitprovider.AuthInfo) gitprovider.Provider {
	return &resolvingProvider{inner: inner, mapErr: func(err error) error {
		apiErr := asAPIError(err)
		if apiErr == nil {
			return err
		}
		switch {
		case apiErr.Status == http.StatusUnauthorized || apiErr.Status == http.StatusForbidden:
			// Permission-scope and rate-limit 403s are not credential
			// failures: surface GitHub's message (e.g. "refusing to allow a
			// GitHub App to create or update workflow ... without the
			// workflows permission") instead of misreporting revoked creds.
			if apiErr.Status == http.StatusForbidden && !apiErr.indicatesRevoked() {
				return fmt.Errorf("gitprovider github: %s %s: %s", apiErr.Method, apiErr.Path, apiErr.Body)
			}
			r.invalidate(owner)
			return &ErrAppCredentialsRevoked{OrgID: orgID, AppID: info.AppID, InstallationID: info.InstallationID, APIBase: info.APIBase}
		case apiErr.Status == http.StatusNotFound && strings.Contains(apiErr.Path, "/access_tokens"):
			r.invalidate(owner)
			return r.notInstalledErr(owner)
		}
		return err
	}}
}

// forTenantBYO implements model B: the tenant's own GitHub App.
func (r *Resolver) forTenantBYO(ctx context.Context, cfg *types.TenantGitConfig) (gitprovider.Provider, *gitprovider.AuthInfo, error) {
	if r.cfg.KeyLoader == nil {
		return nil, nil, fmt.Errorf("gitprovider github: tenant BYO git app configured but no key loader is wired (INARI_TENANT_GIT_KEY_MOUNT_ROOT)")
	}
	key := byoCacheKey(cfg)
	r.mu.Lock()
	cp, ok := r.providers[key]
	r.mu.Unlock()
	if ok {
		return cp.provider, cp.info, nil
	}
	// Single-flight the key load + provider construction: concurrent
	// resolutions for the same credential share one KeyLoader call.
	v, err, _ := r.sf.Do("byo:"+key, func() (any, error) {
		// Re-check inside the flight: another goroutine may have completed
		// while we waited.
		r.mu.Lock()
		cp, ok := r.providers[key]
		r.mu.Unlock()
		if ok {
			return cp, nil
		}
		keyBytes, err := r.cfg.KeyLoader(ctx, cfg.GitHubApp.KeyRef)
		if err != nil {
			return nil, fmt.Errorf("gitprovider github: load tenant app key: %w", err)
		}
		base := strings.TrimSuffix(cfg.GitHubApp.APIBase, "/")
		if base == "" {
			base = "https://api.github.com"
		}
		info := &gitprovider.AuthInfo{
			Model: gitprovider.AuthModelBYO, AppID: cfg.GitHubApp.AppID,
			InstallationID: cfg.GitHubApp.InstallationID, APIBase: base,
		}
		inner := NewWithKey(cfg.GitHubApp.AppID, cfg.GitHubApp.InstallationID, keyBytes, base)
		wrapped := r.wrapBYO(inner, cfg.OrgID, key, info)
		entry := &cachedProvider{provider: wrapped, info: info}
		r.mu.Lock()
		r.providers[key] = entry
		r.mu.Unlock()
		r.emit(ctx, ResolvedEvent{OrgID: cfg.OrgID, AuthModel: info.Model, AppID: info.AppID, InstallationID: info.InstallationID, APIBase: base, Result: "resolved"})
		r.scopeCheck(ctx, inner, cfg.OrgID, cfg.Repo, info)
		return entry, nil
	})
	if err != nil {
		return nil, nil, err
	}
	cp = v.(*cachedProvider)
	return cp.provider, cp.info, nil
}

// wrapBYO maps auth failures to typed errors and evicts the failed BYO
// provider so the next resolution reloads the key (rotation pickup, model
// B). Only the affected credential is evicted — other repos' BYO apps in
// the same org keep their cached providers.
func (r *Resolver) wrapBYO(inner *Provider, orgID, cacheKey string, info *gitprovider.AuthInfo) gitprovider.Provider {
	return &resolvingProvider{inner: inner, mapErr: func(err error) error {
		apiErr := asAPIError(err)
		if apiErr == nil {
			return err
		}
		switch {
		case apiErr.Status == http.StatusUnauthorized || apiErr.Status == http.StatusForbidden:
			if apiErr.Status == http.StatusForbidden && !apiErr.indicatesRevoked() {
				return fmt.Errorf("gitprovider github: %s %s: %s", apiErr.Method, apiErr.Path, apiErr.Body)
			}
			r.evictBYO(cacheKey)
			return &ErrAppCredentialsRevoked{OrgID: orgID, AppID: info.AppID, InstallationID: info.InstallationID, APIBase: info.APIBase}
		case apiErr.Status == http.StatusNotFound && strings.Contains(apiErr.Path, "/access_tokens"):
			r.evictBYO(cacheKey)
			return &ErrAppCredentialsRevoked{OrgID: orgID, AppID: info.AppID, InstallationID: info.InstallationID, APIBase: info.APIBase}
		}
		return err
	}}
}

// evictBYO drops one cached BYO provider by its credential-scoped key.
func (r *Resolver) evictBYO(cacheKey string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.providers, cacheKey)
}

// byoCacheKey scopes a cached BYO provider to its credential identity, not
// just the org: two repos in one org may carry different per-repo BYO apps
// (Feature A), and a per-org key would silently cross-use credentials.
func byoCacheKey(cfg *types.TenantGitConfig) string {
	app := cfg.GitHubApp
	return fmt.Sprintf("t:%s:%d:%d:%s", cfg.OrgID, app.AppID, app.InstallationID, strings.TrimSuffix(app.APIBase, "/"))
}

// EvictTenant drops every cached BYO provider (and the status) for a
// tenant — called after git-config changes so the next deploy picks up new
// creds. Platform (i:) entries belong to installations, not tenants, and
// are left alone.
func (r *Resolver) EvictTenant(orgID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	prefix := "t:" + orgID + ":"
	for k := range r.providers {
		if strings.HasPrefix(k, prefix) {
			delete(r.providers, k)
		}
	}
	// Clear probe statuses: BYO entries (t:orgID:...) and the platform entry.
	for k := range r.status {
		if strings.HasPrefix(k, prefix) || k == "p:"+orgID {
			delete(r.status, k)
		}
	}
}

func (r *Resolver) invalidate(owner string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.installs, strings.ToLower(owner))
}

// seedLegacy resolves the deprecated pinned installation ID once and caches
// its org (back-compat with the old single-org env config). A failed attempt
// (e.g. the caller's ctx was cancelled) does NOT latch — the next request
// retries, so one unlucky request can't silently lose the back-compat seed.
func (r *Resolver) seedLegacy(ctx context.Context) {
	if r.cfg.LegacyInstallationID == 0 {
		return
	}
	r.mu.Lock()
	done := r.legacySeeded
	r.mu.Unlock()
	if done {
		return
	}
	var inst struct {
		ID      int64 `json:"id"`
		Account struct {
			Login string `json:"login"`
		} `json:"account"`
	}
	if err := r.appGet(ctx, fmt.Sprintf("/app/installations/%d", r.cfg.LegacyInstallationID), &inst); err != nil {
		return // best-effort; retried on the next request, discovery is the fallback
	}
	if inst.Account.Login != "" {
		r.mu.Lock()
		r.installs[strings.ToLower(inst.Account.Login)] = installation{id: inst.ID, fetchedAt: r.now()}
		r.legacySeeded = true
		r.mu.Unlock()
	}
}

// discover lists the platform app's installations and warms the cache for
// every org seen (one list call serves all tenants).
func (r *Resolver) discover(ctx context.Context) error {
	now := r.now()
	seen := map[string]installation{}
	for page := 1; ; page++ {
		var batch []struct {
			ID      int64 `json:"id"`
			Account struct {
				Login string `json:"login"`
			} `json:"account"`
		}
		link, err := r.appGetPage(ctx, page, &batch)
		if err != nil {
			return err
		}
		for _, inst := range batch {
			if inst.Account.Login != "" {
				seen[strings.ToLower(inst.Account.Login)] = installation{id: inst.ID, fetchedAt: now}
			}
		}
		if !strings.Contains(link, `rel="next"`) {
			break
		}
	}
	r.mu.Lock()
	for login, inst := range seen {
		r.installs[login] = inst
	}
	r.mu.Unlock()
	return nil
}

// noteNotFound records a negative-cache entry (called by discover callers).
func (r *Resolver) noteNotFound(login string) {
	r.mu.Lock()
	r.installs[strings.ToLower(login)] = installation{fetchedAt: r.now(), notFound: true}
	r.mu.Unlock()
}

// appGet performs one App-JWT-authenticated GET against the platform base.
func (r *Resolver) appGet(ctx context.Context, path string, out any) error {
	_, err := r.appGetURL(ctx, r.apiBase+path, out)
	return err
}

// appGetPage GETs one installations page, returning the Link header.
func (r *Resolver) appGetPage(ctx context.Context, page int, out any) (string, error) {
	return r.appGetURL(ctx, fmt.Sprintf("%s/app/installations?per_page=100&page=%d", r.apiBase, page), out)
}

func (r *Resolver) appGetURL(ctx context.Context, url string, out any) (string, error) {
	tok, err := signAppJWT(r.cfg.PlatformAppID, r.platformKey)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := r.http.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return "", &APIError{Method: http.MethodGet, Path: url, Status: resp.StatusCode}
	}
	return resp.Header.Get("Link"), json.NewDecoder(resp.Body).Decode(out)
}

// scopeCheck records a (non-blocking) warning when a "selected"-scoped
// installation does not cover the target repo — the classic
// installed-but-not-granted misconfiguration. "all"-scoped installations
// are broad but functional: no warning. Repo names are arbitrary (Feature
// A team repos), so the check is repo-aware, not name-pattern-based.
// Paginates through all installation repos (100 per page). Tolerates GHE
// skew (404/405).
func (r *Resolver) scopeCheck(ctx context.Context, p *Provider, orgID, repo string, info *gitprovider.AuthInfo) {
	_, name, err := splitRepo(repo)
	if err != nil {
		return // advisory only
	}
	for page := 1; page <= 50; page++ { // 5000-repo safety cap
		var out struct {
			Selection string `json:"repository_selection"`
			Repos     []struct {
				Name string `json:"name"`
			} `json:"repositories"`
		}
		path := fmt.Sprintf("/installation/repositories?per_page=100&page=%d", page)
		if _, err := p.do(ctx, http.MethodGet, path, nil, &out); err != nil {
			return // advisory only
		}
		if page == 1 && out.Selection != "selected" {
			return
		}
		for _, rp := range out.Repos {
			if strings.EqualFold(rp.Name, name) {
				return
			}
		}
		if len(out.Repos) == 0 {
			break
		}
	}
	r.emit(ctx, ResolvedEvent{OrgID: orgID, AuthModel: info.Model, AppID: info.AppID, InstallationID: info.InstallationID, APIBase: info.APIBase, Result: "scope_warning"})
}

// Probe health-checks a tenant's git provider auth (cached 60s). The cache
// key includes the credential identity so per-repo BYO apps within one org
// don't collide (Feature A).
func (r *Resolver) Probe(ctx context.Context, cfg *types.TenantGitConfig) *types.GitProviderStatus {
	key := probeCacheKey(cfg)
	r.mu.Lock()
	entry, ok := r.status[key]
	r.mu.Unlock()
	if ok && r.now().Sub(entry.checkedAt) < time.Minute {
		return entry.status
	}
	st := r.probe(ctx, cfg)
	r.mu.Lock()
	r.status[key] = statusEntry{status: st, checkedAt: r.now()}
	r.mu.Unlock()
	return st
}

// probeCacheKey scopes the probe cache to the credential identity: BYO apps
// key by their app+installation; the platform app keys by org (one platform
// installation per git-org).
func probeCacheKey(cfg *types.TenantGitConfig) string {
	if cfg.GitHubApp != nil {
		return byoCacheKey(cfg)
	}
	return "p:" + cfg.OrgID
}

func (r *Resolver) probe(ctx context.Context, cfg *types.TenantGitConfig) *types.GitProviderStatus {
	st := &types.GitProviderStatus{State: "unknown", CheckedAt: r.now().UTC()}
	p, info, err := r.ForTenant(ctx, cfg)
	if err != nil {
		var ni *ErrAppNotInstalled
		if errors.As(err, &ni) {
			st.State = "not_installed"
		}
		st.AuthModel = string(authModelOf(cfg))
		return st
	}
	st.AuthModel = string(info.Model)
	st.InstallationID = info.InstallationID
	st.APIBase = info.APIBase
	probe, ok := p.(*resolvingProvider)
	if !ok {
		st.State = "unknown"
		return st
	}
	var out struct {
		TotalCount int `json:"total_count"`
	}
	_, err = probe.inner.do(ctx, http.MethodGet, "/installation/repositories?per_page=1", nil, &out)
	if err == nil {
		st.State = "ok"
		return st
	}
	apiErr := asAPIError(err)
	if apiErr == nil {
		return st
	}
	switch apiErr.Status {
	case http.StatusUnauthorized, http.StatusForbidden:
		st.State = "invalid_credentials"
	case http.StatusTooManyRequests:
		st.State = "rate_limited"
	}
	return st
}

func authModelOf(cfg *types.TenantGitConfig) gitprovider.AuthModel {
	if cfg.GitHubApp != nil {
		return gitprovider.AuthModelBYO
	}
	return gitprovider.AuthModelPlatform
}

func asAPIError(err error) *APIError {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr
	}
	return nil
}

// resolvingProvider delegates to a *Provider, mapping errors (invalidation,
// typed credential errors) through the resolver.
type resolvingProvider struct {
	inner  *Provider
	mapErr func(error) error
}

func (p *resolvingProvider) EnsureRepo(ctx context.Context, repo string) (string, error) {
	u, err := p.inner.EnsureRepo(ctx, repo)
	return u, p.mapErr(err)
}

func (p *resolvingProvider) CommitFiles(ctx context.Context, repo, branch string, files []gitprovider.File, message string) (*gitprovider.Result, error) {
	res, err := p.inner.CommitFiles(ctx, repo, branch, files, message)
	return res, p.mapErr(err)
}

func (p *resolvingProvider) DeleteFiles(ctx context.Context, repo, branch string, paths []string, message string) (*gitprovider.Result, error) {
	res, err := p.inner.DeleteFiles(ctx, repo, branch, paths, message)
	return res, p.mapErr(err)
}

func (p *resolvingProvider) OpenPR(ctx context.Context, repo, base, title, body string, files []gitprovider.File) (*gitprovider.Result, error) {
	res, err := p.inner.OpenPR(ctx, repo, base, title, body, files)
	return res, p.mapErr(err)
}

func (p *resolvingProvider) ReadFile(ctx context.Context, repo, branch, path string) (string, error) {
	s, err := p.inner.ReadFile(ctx, repo, branch, path)
	return s, p.mapErr(err)
}

// webBaseFrom derives the clone-URL host from an API base.
func webBaseFrom(apiBase string) string {
	if apiBase == "https://api.github.com" {
		return "https://github.com"
	}
	return strings.TrimSuffix(apiBase, "/api/v3")
}
