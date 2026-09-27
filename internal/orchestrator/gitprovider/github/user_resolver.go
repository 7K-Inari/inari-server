package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
)

// Connection carries the non-secret metadata of one per-user git
// connection (model C). Token material never crosses this seam.
type Connection struct {
	ID            string // user_git_connections row id (ugc:...)
	Provider      string // e.g. "github"
	ProviderLogin string // git host login used for commit attribution
	APIBase       string // empty = github.com; GHE https://host/api/v3
}

// ErrConnectionNotFound is the sentinel a LookupConnectionFunc returns when
// the user has no connection for the provider.
var ErrConnectionNotFound = errors.New("gitprovider github: no user git connection")

// LookupConnectionFunc loads one user's connection metadata. Wired to
// usergit.Service in cmd/inari-server; fakes drive tests.
type LookupConnectionFunc func(ctx context.Context, orgID, userSub, provider string) (*Connection, error)

// ErrNoConnection: the user has not connected a git identity. Model C
// fails closed — callers must never fall back to a platform/tenant app.
type ErrNoConnection struct {
	OrgID    string
	UserSub  string
	Provider string
}

func (e *ErrNoConnection) Error() string {
	return fmt.Sprintf("gitprovider github: user %s has no %s git connection (tenant %s); connect one under git settings", e.UserSub, e.Provider, e.OrgID)
}

// ErrUserTokenInvalid: the provider rejected the user's access token
// mid-flight (revoked/expired grant). The user must reconnect.
type ErrUserTokenInvalid struct {
	OrgID        string
	UserSub      string
	ConnectionID string
}

func (e *ErrUserTokenInvalid) Error() string {
	return fmt.Sprintf("gitprovider github: user token rejected for connection %s (tenant %s); the user must reconnect their git identity", e.ConnectionID, e.OrgID)
}

// ErrAPIBaseNotAllowed: the connection's GHE API base is outside the
// configured allowlist (or not https).
type ErrAPIBaseNotAllowed struct {
	APIBase string
}

func (e *ErrAPIBaseNotAllowed) Error() string {
	return fmt.Sprintf("gitprovider github: api base %q is not in the user-git allowlist (https only)", e.APIBase)
}

// UserResolverConfig configures the model-C resolver.
type UserResolverConfig struct {
	// Tokens mints/caches user access tokens (usergit.Service).
	Tokens gitprovider.UserTokens
	// Lookup loads connection metadata (usergit.Service adapter).
	Lookup LookupConnectionFunc
	// AllowedAPIBases allowlists GHE API base URLs; empty permits only
	// github.com.
	AllowedAPIBases []string
	// OnResolved is invoked on resolution events (audit hook).
	OnResolved func(ctx context.Context, ev ResolvedEvent)
}

// UserResolver resolves gitprovider.Provider for one user's connected git
// identity (model C). Stateless: providers are built per call — usergit
// owns token caching, so there is nothing worth caching here.
type UserResolver struct {
	cfg       UserResolverConfig
	allowlist map[string]bool
}

// NewUserResolver validates the allowlist and prepares the resolver.
func NewUserResolver(cfg UserResolverConfig) (*UserResolver, error) {
	if cfg.Tokens == nil || cfg.Lookup == nil {
		return nil, errors.New("gitprovider github user resolver: Tokens and Lookup are required")
	}
	allow := map[string]bool{}
	for _, base := range cfg.AllowedAPIBases {
		u, err := url.Parse(base)
		if err != nil || u.Host == "" || (u.Scheme != "https" && !isLoopbackHTTP(u)) {
			return nil, fmt.Errorf("gitprovider github user resolver: invalid allowed api base %q (https URL required)", base)
		}
		allow[strings.ToLower(u.Host)] = true
	}
	return &UserResolver{cfg: cfg, allowlist: allow}, nil
}

// isLoopbackHTTP permits http api bases only for loopback hosts (dev/tests),
// mirroring the W4 usergit guard.
func isLoopbackHTTP(u *url.URL) bool {
	if u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func (r *UserResolver) emit(ctx context.Context, ev ResolvedEvent) {
	if r.cfg.OnResolved != nil {
		r.cfg.OnResolved(ctx, ev)
	}
}

// checkAPIBase enforces the GHE allowlist (empty apiBase = github.com,
// always allowed). Returns the effective API base.
func (r *UserResolver) checkAPIBase(apiBase string) (string, error) {
	if apiBase == "" {
		return "https://api.github.com", nil
	}
	u, err := url.Parse(apiBase)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !isLoopbackHTTP(u)) {
		return "", &ErrAPIBaseNotAllowed{APIBase: apiBase}
	}
	if !r.allowlist[strings.ToLower(u.Host)] {
		return "", &ErrAPIBaseNotAllowed{APIBase: apiBase}
	}
	return strings.TrimSuffix(apiBase, "/"), nil
}

// ForUser resolves the Provider for the user's GitHub connection. Fails
// closed with *ErrNoConnection when no connection exists.
func (r *UserResolver) ForUser(ctx context.Context, orgID, userSub string) (gitprovider.Provider, *gitprovider.AuthInfo, error) {
	const provider = "github"
	conn, err := r.cfg.Lookup(ctx, orgID, userSub, provider)
	if errors.Is(err, ErrConnectionNotFound) {
		r.emit(ctx, ResolvedEvent{OrgID: orgID, AuthModel: gitprovider.AuthModelUser, UserSub: userSub, Result: "not_connected"})
		return nil, nil, &ErrNoConnection{OrgID: orgID, UserSub: userSub, Provider: provider}
	}
	if err != nil {
		r.emit(ctx, ResolvedEvent{OrgID: orgID, AuthModel: gitprovider.AuthModelUser, UserSub: userSub, Result: "error"})
		return nil, nil, err
	}
	base, err := r.checkAPIBase(conn.APIBase)
	if err != nil {
		r.emit(ctx, ResolvedEvent{OrgID: orgID, AuthModel: gitprovider.AuthModelUser, UserSub: userSub, ConnectionID: conn.ID, Result: "error"})
		return nil, nil, err
	}
	tokenFunc := func(ctx context.Context) (string, error) {
		return r.cfg.Tokens.AccessToken(ctx, orgID, userSub, provider)
	}
	inner := NewUserProvider(tokenFunc, base, UserIdentity{Login: conn.ProviderLogin})
	info := &gitprovider.AuthInfo{
		Model:         gitprovider.AuthModelUser,
		APIBase:       base,
		UserSub:       userSub,
		ConnectionID:  conn.ID,
		ProviderLogin: conn.ProviderLogin,
	}
	wrapped := &resolvingProvider{inner: inner, mapErr: func(err error) error {
		apiErr := asAPIError(err)
		if apiErr == nil {
			return err
		}
		if apiErr.Status == http.StatusUnauthorized {
			return &ErrUserTokenInvalid{OrgID: orgID, UserSub: userSub, ConnectionID: conn.ID}
		}
		return err
	}}
	r.emit(ctx, ResolvedEvent{
		OrgID: orgID, AuthModel: gitprovider.AuthModelUser, APIBase: base,
		UserSub: userSub, ConnectionID: conn.ID, Result: "resolved",
	})
	return wrapped, info, nil
}
