package gitprovider

import (
	"context"

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
)

// AuthInfo attributes a resolved Provider to its credential context, for
// audit trails (every git write is attributable per tenant + host).
type AuthInfo struct {
	Model          AuthModel
	AppID          int64
	InstallationID int64
	// APIBase is the effective GitHub API base (empty = github.com).
	APIBase string
}

// Resolver returns the Provider bound to one tenant's credentials context.
// Implementations may cache providers; callers MUST NOT retain providers
// across requests (credentials rotate out-of-band).
type Resolver interface {
	ForTenant(ctx context.Context, cfg *types.TenantGitConfig) (Provider, *AuthInfo, error)
}

// StaticResolver wraps a single Provider (fake/dev and legacy wiring).
type StaticResolver struct{ P Provider }

func (s StaticResolver) ForTenant(context.Context, *types.TenantGitConfig) (Provider, *AuthInfo, error) {
	return s.P, &AuthInfo{Model: AuthModelStatic}, nil
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
