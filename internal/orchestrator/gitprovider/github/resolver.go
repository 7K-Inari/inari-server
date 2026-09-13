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
	Result         string // resolved|scope_warning|not_installed|error
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
	cfg         ResolverConfig
	platformKey *rsa.PrivateKey
	apiBase     string
	http        *http.Client
	now         func() time.Time

	mu        sync.Mutex
	installs  map[string]installation // key: lower(account.login)
	providers map[string]*cachedProvider
	status    map[string]statusEntry

	seedOnce sync.Once
	sf       singleflight.Group
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
		return r.platformProvider(ctx, cfg.OrgID, owner, inst.id)
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
	return r.platformProvider(ctx, cfg.OrgID, owner, inst.id)
}

func (r *Resolver) notInstalledErr(org string) *ErrAppNotInstalled {
	return &ErrAppNotInstalled{Org: org, InstallURL: webBaseFrom(r.apiBase) + "/apps/" + r.cfg.PlatformAppSlug + "/installations/new"}
}

// platformProvider returns the cached provider for one installation.
func (r *Resolver) platformProvider(ctx context.Context, orgID, owner string, installationID int64) (gitprovider.Provider, *gitprovider.AuthInfo, error) {
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
	r.scopeCheck(ctx, inner, orgID, info)
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
	key := "t:" + cfg.OrgID
	r.mu.Lock()
	cp, ok := r.providers[key]
	r.mu.Unlock()
	if ok {
		return cp.provider, cp.info, nil
	}
	keyBytes, err := r.cfg.KeyLoader(ctx, cfg.GitHubApp.KeyRef)
	if err != nil {
		return nil, nil, fmt.Errorf("gitprovider github: load tenant app key: %w", err)
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
	wrapped := r.wrapBYO(inner, cfg.OrgID, info)
	r.mu.Lock()
	r.providers[key] = &cachedProvider{provider: wrapped, info: info}
	r.mu.Unlock()
	r.emit(ctx, ResolvedEvent{OrgID: cfg.OrgID, AuthModel: info.Model, AppID: info.AppID, InstallationID: info.InstallationID, APIBase: base, Result: "resolved"})
	r.scopeCheck(ctx, inner, cfg.OrgID, info)
	return wrapped, info, nil
}

// wrapBYO maps auth failures to typed errors and evicts the tenant provider
// so the next resolution reloads the key (rotation pickup, model B).
func (r *Resolver) wrapBYO(inner *Provider, orgID string, info *gitprovider.AuthInfo) gitprovider.Provider {
	return &resolvingProvider{inner: inner, mapErr: func(err error) error {
		apiErr := asAPIError(err)
		if apiErr == nil {
			return err
		}
		switch {
		case apiErr.Status == http.StatusUnauthorized || apiErr.Status == http.StatusForbidden:
			r.EvictTenant(orgID)
			return &ErrAppCredentialsRevoked{OrgID: orgID, AppID: info.AppID, InstallationID: info.InstallationID, APIBase: info.APIBase}
		case apiErr.Status == http.StatusNotFound && strings.Contains(apiErr.Path, "/access_tokens"):
			r.EvictTenant(orgID)
			return &ErrAppCredentialsRevoked{OrgID: orgID, AppID: info.AppID, InstallationID: info.InstallationID, APIBase: info.APIBase}
		}
		return err
	}}
}

// EvictTenant drops the cached BYO provider (and status) for a tenant —
// called after git-config changes so the next deploy picks up new creds.
func (r *Resolver) EvictTenant(orgID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.providers, "t:"+orgID)
	delete(r.status, orgID)
}

func (r *Resolver) invalidate(owner string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.installs, strings.ToLower(owner))
}

// seedLegacy resolves the deprecated pinned installation ID once and caches
// its org (back-compat with the old single-org env config).
func (r *Resolver) seedLegacy(ctx context.Context) {
	r.seedOnce.Do(func() {
		if r.cfg.LegacyInstallationID == 0 {
			return
		}
		var inst struct {
			ID      int64 `json:"id"`
			Account struct {
				Login string `json:"login"`
			} `json:"account"`
		}
		if err := r.appGet(ctx, fmt.Sprintf("/app/installations/%d", r.cfg.LegacyInstallationID), &inst); err != nil {
			return // best-effort; discovery will handle failures later
		}
		if inst.Account.Login != "" {
			r.mu.Lock()
			r.installs[strings.ToLower(inst.Account.Login)] = installation{id: inst.ID, fetchedAt: r.now()}
			r.mu.Unlock()
		}
	})
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

// scopeCheck records a (non-blocking) warning when an installation is
// scoped broader than the *-inari-state repos. Tolerates GHE skew (404/405).
func (r *Resolver) scopeCheck(ctx context.Context, p *Provider, orgID string, info *gitprovider.AuthInfo) {
	var out struct {
		Selection string `json:"repository_selection"`
		Repos     []struct {
			Name string `json:"name"`
		} `json:"repositories"`
	}
	if _, err := p.do(ctx, http.MethodGet, "/installation/repositories?per_page=100", nil, &out); err != nil {
		return // advisory only
	}
	broad := out.Selection != "selected"
	if !broad {
		for _, repo := range out.Repos {
			if !strings.HasSuffix(repo.Name, "-inari-state") {
				broad = true
				break
			}
		}
	}
	if broad {
		r.emit(ctx, ResolvedEvent{OrgID: orgID, AuthModel: info.Model, AppID: info.AppID, InstallationID: info.InstallationID, APIBase: info.APIBase, Result: "scope_warning"})
	}
}

// Probe health-checks a tenant's git provider auth (cached 60s).
func (r *Resolver) Probe(ctx context.Context, cfg *types.TenantGitConfig) *types.GitProviderStatus {
	r.mu.Lock()
	entry, ok := r.status[cfg.OrgID]
	r.mu.Unlock()
	if ok && r.now().Sub(entry.checkedAt) < time.Minute {
		return entry.status
	}
	st := r.probe(ctx, cfg)
	r.mu.Lock()
	r.status[cfg.OrgID] = statusEntry{status: st, checkedAt: r.now()}
	r.mu.Unlock()
	return st
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
