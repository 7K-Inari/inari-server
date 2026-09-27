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
