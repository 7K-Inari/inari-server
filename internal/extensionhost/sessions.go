// oidc-sso-session provider surface (plan §5.8, per-user third-party SSO
// sessions — e.g. ArgoCD's own SSO): extensions that proxy to a system with
// its own login flow declare oidc-sso-session; the per-user session lives in
// an encrypted store (table + encryption owned by the W3 task) behind the
// SessionStore seam defined here. This package never decrypts beyond the
// store boundary and never returns raw third-party tokens to the API.
//
// Bootstrap/re-auth: a missing or expired session fails closed with
// ErrReauthRequired; the proxy maps it to 401 + X-Inari-Reauth so the UI can
// drive the provider's login flow and retry.
package extensionhost

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrSessionNotFound: no session exists for (user, extension, provider) —
// bootstrap required. Mapped to the re-auth signal.
var ErrSessionNotFound = errors.New("extensionhost: user session not found")

// ErrReauthRequired: the session exists but is expired/invalid and the user
// must re-authenticate with the third-party provider.
type ErrReauthRequired struct {
	Provider string
}

func (e *ErrReauthRequired) Error() string {
	return fmt.Sprintf("extensionhost: re-authentication required for %s", e.Provider)
}

// UserSession is a per-user third-party session. Credential is the
// downstream-usable credential material returned by the store (the store is
// the encryption boundary — at rest it is ciphertext). It is never persisted
// here, never logged, and never exposed via the API.
type UserSession struct {
	Provider   string
	Credential string
	Expiry     time.Time
}

// SessionStore is the per-user session persistence seam. The Postgres-backed
// encrypted implementation is owned by the W3 task; this package codes
// against the interface only (no migration changes here).
type SessionStore interface {
	Get(ctx context.Context, userSub, extensionName, provider string) (*UserSession, error)
	Put(ctx context.Context, userSub, extensionName string, session *UserSession) error
	Delete(ctx context.Context, userSub, extensionName, provider string) error
}

// ssoSessionProvider resolves oidc-sso-session credentials from the session
// store. Fail closed: no store, no session, or an expired session all block
// the request with a re-auth signal.
type ssoSessionProvider struct {
	sessions SessionStore
	now      func() time.Time
}

func (p *ssoSessionProvider) Name() AuthMethod { return AuthMethodOIDCSSOSession }

func (p *ssoSessionProvider) Resolve(ctx context.Context, req ConnectionRequest) (*ResolvedAuth, error) {
	provider := req.Declared.Audience // for sso sessions, `audience` names the third-party provider (e.g. "argocd")
	if provider == "" {
		provider = req.Extension.Name
	}
	if p.sessions == nil {
		return nil, &ErrReauthRequired{Provider: provider}
	}
	now := time.Now
	if p.now != nil {
		now = p.now
	}
	sess, err := p.sessions.Get(ctx, req.Identity.Subject, req.Extension.Name, provider)
	if errors.Is(err, ErrSessionNotFound) {
		return nil, &ErrReauthRequired{Provider: provider}
	}
	if err != nil {
		return nil, fmt.Errorf("extensionhost: session store: %w", err)
	}
	if sess == nil || (!sess.Expiry.IsZero() && !now().Before(sess.Expiry)) || sess.Credential == "" {
		return nil, &ErrReauthRequired{Provider: provider}
	}
	return &ResolvedAuth{Audience: provider, DownstreamToken: sess.Credential}, nil
}
