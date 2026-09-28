package usergit

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrInvalidInput: caller-supplied input failed validation (e.g. an
	// apiBase that is not allowlisted).
	ErrInvalidInput = errors.New("usergit: invalid input")
	// ErrUnknownProvider: no provider registered under the name.
	ErrUnknownProvider = errors.New("usergit: unknown provider")
	// ErrProviderNotEnabled: the provider exists in the registry but has no
	// implementation yet (planned: gitlab, forgejo).
	ErrProviderNotEnabled = errors.New("usergit: provider not enabled")
	// ErrGrantInvalid: the provider permanently rejected the presented
	// grant (rotated, revoked, or replayed refresh token). Fail closed.
	ErrGrantInvalid = errors.New("usergit: grant rejected by provider")
	// ErrConnectionCompromised: a refresh-token replay was detected; the
	// connection was wiped and must be re-established.
	ErrConnectionCompromised = errors.New("usergit: connection wiped after refresh-token replay")
)

// TokenGrant is the result of an OAuth exchange/refresh. AccessExpiry is
// zero when the provider does not expire access tokens.
type TokenGrant struct {
	AccessToken   string
	RefreshToken  string // empty = provider did not rotate; keep the stored one
	Scopes        string
	ProviderLogin string
	AccessExpiry  time.Time
}

// Provider abstracts a per-user git OAuth provider (github; gitlab and
// forgejo planned behind the same interface).
type Provider interface {
	Name() string
	// Configured reports whether the provider holds working credentials
	// and can run the OAuth flow. Unconfigured providers (placeholders,
	// partially configured implementations) are hidden from the provider
	// listing and rejected at authorize time with ErrProviderNotEnabled.
	Configured() bool
	// AuthorizeURL builds the provider consent URL for the flow.
	AuthorizeURL(state, codeChallenge, apiBase string) (string, error)
	// Exchange trades an authorization code (+ PKCE verifier) for tokens.
	Exchange(ctx context.Context, code, codeVerifier, apiBase string) (*TokenGrant, error)
	// Refresh rotates the refresh token and mints an access token.
	// ErrGrantInvalid means the presented refresh token was rejected.
	Refresh(ctx context.Context, refreshToken, apiBase string) (*TokenGrant, error)
	// Revoke tears down the provider-side grant. Best-effort on
	// disconnect; already-revoked is success.
	Revoke(ctx context.Context, accessToken, apiBase string) error
}

// PlannedProvider is a registry placeholder for providers whose
// implementation lands in a later wave (gitlab, forgejo).
type PlannedProvider struct{ ProviderName string }

func (p PlannedProvider) Name() string { return p.ProviderName }

func (p PlannedProvider) Configured() bool { return false }

func (p PlannedProvider) AuthorizeURL(string, string, string) (string, error) {
	return "", ErrProviderNotEnabled
}

func (p PlannedProvider) Exchange(context.Context, string, string, string) (*TokenGrant, error) {
	return nil, ErrProviderNotEnabled
}

func (p PlannedProvider) Refresh(context.Context, string, string) (*TokenGrant, error) {
	return nil, ErrProviderNotEnabled
}

func (p PlannedProvider) Revoke(context.Context, string, string) error {
	return ErrProviderNotEnabled
}
