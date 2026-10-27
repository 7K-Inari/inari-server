package gitprovider

import (
	"context"
	"errors"

	"github.com/7K-Inari/inari-server/internal/types"
)

// AuthModel identifies which credential model produced a Provider.
type AuthModel string

const (
	// AuthModelPlatform is the platform GitHub App with a per-org
	// installation resolved at runtime (model A).
	AuthModelPlatform AuthModel = "platform"
	// AuthModelBYO is a tenant-supplied GitHub App (model B override).
	AuthModelBYO AuthModel = "byo"
	// AuthModelStatic is a fixed provider (fake/dev or legacy wiring).
	AuthModelStatic AuthModel = "static"
	// AuthModelUser is the calling user's own git identity (model C): a
	// per-user OAuth connection (ADR-0012) minting user access tokens.
	AuthModelUser AuthModel = "user"
)

// AuthInfo attributes a resolved Provider to its credential context, for
// audit trails (every git write is attributable per tenant + host).
type AuthInfo struct {
	Model          AuthModel
	AppID          int64
	InstallationID int64
	// APIBase is the effective GitHub API base (empty = github.com).
	APIBase string
	// Model C fields (empty for platform/BYO/static).
	// UserSub is the JWT subject of the connected user; ConnectionID is the
	// user_git_connections row id; ProviderLogin is the git host login used
	// for commit attribution.
	UserSub       string
	ConnectionID  string
	ProviderLogin string
}

// UserTokens is the narrow W5 seam into usergit.Service (ADR-0012): it
// mints (and caches in memory) a short-lived user access token for the
// caller's per-user git connection. Token material never crosses this
// interface in logs or audit metadata — identifiers only.
type UserTokens interface {
	AccessToken(ctx context.Context, orgID, userSub, provider string) (string, error)
}

// Resolver returns the Provider bound to one tenant's credentials context.
// Implementations may cache providers; callers MUST NOT retain providers
// across requests (credentials rotate out-of-band).
type Resolver interface {
	ForTenant(ctx context.Context, cfg *types.TenantGitConfig) (Provider, *AuthInfo, error)
	// ForUser resolves the Provider bound to one user's connected git
	// identity (model C). Implementations MUST fail closed (typed error)
	// when the user has no connection — never fall back to a platform or
	// tenant app credential in this layer.
	ForUser(ctx context.Context, orgID, userSub string) (Provider, *AuthInfo, error)
}

// ErrUserModelUnsupported is returned by resolvers that cannot authenticate
// as an end user (static/fake/local wiring).
var ErrUserModelUnsupported = errors.New("gitprovider: user auth model unsupported by this resolver")

// RepoSelectorDefault selects the org's default repo row. Selectors are row
// IDs (ULIDs), never names, so the sentinel cannot collide with a real row.
const RepoSelectorDefault = "default"

// RepoStore is the narrow registry seam RepoResolver needs (implemented by
// inventory.Store).
type RepoStore interface {
	GetGitRepo(ctx context.Context, orgID, id string) (*types.TenantGitRepo, error)
	GetDefaultGitRepo(ctx context.Context, orgID string) (*types.TenantGitRepo, error)
}

// OrgGitConfigs exposes the org-wide BYO GitHub App reference from
// tenant_git_configs (the middle tier of the credential precedence:
// per-repo BYO → org-wide app → platform app). A nil return means the org
// has no org-wide app configured.
type OrgGitConfigs interface {
	OrgGitHubApp(ctx context.Context, orgID string) (*types.GitHubAppConfig, error)
}

// RepoResolver resolves git credentials for a registry repo row (Feature A):
// it looks the row up by ID (or RepoSelectorDefault), merges the credential
// precedence (per-repo BYO override → org-wide app → platform app), and
// delegates to the credential Resolver.
type RepoResolver struct {
	repos RepoStore
	orgs  OrgGitConfigs
	inner Resolver
}

// NewRepoResolver wires the facade. orgs may be nil (no org-wide fallback).
func NewRepoResolver(repos RepoStore, orgs OrgGitConfigs, inner Resolver) *RepoResolver {
	return &RepoResolver{repos: repos, orgs: orgs, inner: inner}
}

// ResolveRepo returns the repo row plus the Provider/AuthInfo resolved with
// the effective credentials for that row.
func (rr *RepoResolver) ResolveRepo(ctx context.Context, orgID, selector string) (*types.TenantGitRepo, Provider, *AuthInfo, error) {
	row, err := rr.repoRow(ctx, orgID, selector)
	if err != nil {
		return nil, nil, nil, err
	}
	p, info, err := rr.ResolveRow(ctx, row)
	if err != nil {
		return nil, nil, nil, err
	}
	return row, p, info, nil
}

// ResolveRow resolves credentials for an in-memory repo row — used by the
// registry itself, which already holds the row (including candidate rows
// not yet persisted, at registration time).
func (rr *RepoResolver) ResolveRow(ctx context.Context, row *types.TenantGitRepo) (Provider, *AuthInfo, error) {
	cfg, err := rr.effectiveConfig(ctx, row.OrgID, row)
	if err != nil {
		return nil, nil, err
	}
	return rr.inner.ForTenant(ctx, cfg)
}

// ValidateRepo resolves credentials for the row without returning a
// provider — the registration-time fail-fast check (decision 3c). Typed
// errors (ErrAppNotInstalled with install URL, ErrAppCredentialsRevoked)
// propagate from the underlying resolver.
func (rr *RepoResolver) ValidateRepo(ctx context.Context, row *types.TenantGitRepo) error {
	_, _, err := rr.ResolveRow(ctx, row)
	return err
}

// ProbeRepo health-checks the row's git provider auth with the effective
// (precedence-merged) credentials, reusing the inner resolver's Probe seam
// when it has one; otherwise it degrades to "unknown".
func (rr *RepoResolver) ProbeRepo(ctx context.Context, row *types.TenantGitRepo) *types.GitProviderStatus {
	prober, ok := rr.inner.(interface {
		Probe(context.Context, *types.TenantGitConfig) *types.GitProviderStatus
	})
	if !ok {
		return &types.GitProviderStatus{State: "unknown", AuthModel: "static"}
	}
	cfg, err := rr.effectiveConfig(ctx, row.OrgID, row)
	if err != nil {
		return &types.GitProviderStatus{State: "unknown"}
	}
	return prober.Probe(ctx, cfg)
}

func (rr *RepoResolver) repoRow(ctx context.Context, orgID, selector string) (*types.TenantGitRepo, error) {
	if selector == "" || selector == RepoSelectorDefault {
		return rr.repos.GetDefaultGitRepo(ctx, orgID)
	}
	return rr.repos.GetGitRepo(ctx, orgID, selector)
}

// effectiveConfig merges the repo row with the credential precedence:
// the row's own BYO app wins; otherwise the org-wide app from
// tenant_git_configs; otherwise nil (platform app, model A).
func (rr *RepoResolver) effectiveConfig(ctx context.Context, orgID string, row *types.TenantGitRepo) (*types.TenantGitConfig, error) {
	app := row.GitHubApp
	if app == nil && rr.orgs != nil {
		orgApp, err := rr.orgs.OrgGitHubApp(ctx, orgID)
		if err != nil {
			return nil, err
		}
		app = orgApp
	}
	return &types.TenantGitConfig{
		OrgID: orgID, Repo: row.Repo,
		CommitPolicy: row.CommitPolicy, BaseBranch: row.BaseBranch,
		GitHubApp: app,
	}, nil
}

// StaticResolver wraps a single Provider (fake/dev and legacy wiring).
type StaticResolver struct{ P Provider }

func (s StaticResolver) ForTenant(context.Context, *types.TenantGitConfig) (Provider, *AuthInfo, error) {
	return s.P, &AuthInfo{Model: AuthModelStatic}, nil
}

// ForUser fails closed: static resolvers never impersonate a user.
func (s StaticResolver) ForUser(context.Context, string, string) (Provider, *AuthInfo, error) {
	return nil, nil, ErrUserModelUnsupported
}

// PerRepo adapts a Resolver to the plain Provider interface for modules that
// address repos directly (scaffolding, tenant zone factory): each call
// resolves credentials for the repo's owner via the platform app (model A —
// BYO tenant overrides never apply to platform-owned orgs).
type PerRepo struct{ R Resolver }

func (a PerRepo) resolve(ctx context.Context, repo string) (Provider, error) {
	p, _, err := a.R.ForTenant(ctx, &types.TenantGitConfig{Repo: repo})
	return p, err
}

func (a PerRepo) EnsureRepo(ctx context.Context, repo string) (string, error) {
	p, err := a.resolve(ctx, repo)
	if err != nil {
		return "", err
	}
	return p.EnsureRepo(ctx, repo)
}

func (a PerRepo) CommitFiles(ctx context.Context, repo, branch string, files []File, message string) (*Result, error) {
	p, err := a.resolve(ctx, repo)
	if err != nil {
		return nil, err
	}
	return p.CommitFiles(ctx, repo, branch, files, message)
}

func (a PerRepo) DeleteFiles(ctx context.Context, repo, branch string, paths []string, message string) (*Result, error) {
	p, err := a.resolve(ctx, repo)
	if err != nil {
		return nil, err
	}
	return p.DeleteFiles(ctx, repo, branch, paths, message)
}

func (a PerRepo) OpenPR(ctx context.Context, repo, base, title, body string, files []File) (*Result, error) {
	p, err := a.resolve(ctx, repo)
	if err != nil {
		return nil, err
	}
	return p.OpenPR(ctx, repo, base, title, body, files)
}

func (a PerRepo) ReadFile(ctx context.Context, repo, branch, path string) (string, error) {
	p, err := a.resolve(ctx, repo)
	if err != nil {
		return "", err
	}
	return p.ReadFile(ctx, repo, branch, path)
}

// EnsureWebhook implements Provider (platform-app credentials).
func (a PerRepo) EnsureWebhook(ctx context.Context, repo string, cfg WebhookConfig) (string, error) {
	p, err := a.resolve(ctx, repo)
	if err != nil {
		return "", err
	}
	return p.EnsureWebhook(ctx, repo, cfg)
}
