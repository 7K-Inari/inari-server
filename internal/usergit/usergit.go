// Package usergit implements the W4 per-user git connection core (plan:
// Extension OIDC Pass-Through & Per-User Git Social Login): users connect
// their own git identity (GitHub App user OAuth first; GitLab/Forgejo
// planned) so user-attributed git operations can mint short-lived access
// tokens from a stored, envelope-encrypted refresh token.
//
// Security invariants:
//   - only the refresh token is persisted, envelope-encrypted with a
//     per-row DEK and AAD bound to the row ID; access tokens live in an
//     in-memory cache only;
//   - rotated refresh tokens are persisted before the new access token is
//     ever used; refreshes are single-flighted per connection;
//   - a provider-rejected (replayed) refresh token wipes the connection and
//     emits a user_git.compromised audit/outbox event;
//   - token material never appears in logs, errors, audit payloads, or
//     REST responses.
package usergit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/sync/singleflight"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// Config tunes the user git connection service.
type Config struct {
	// UIReturnURL is where the callback redirects the browser on
	// success/failure (default "/settings/git").
	UIReturnURL string
	// StateTTL bounds OAuth state lifetime (default 10m).
	StateTTL time.Duration
	// AccessCacheSkew is subtracted from access-token expiry before reuse
	// (default 60s).
	AccessCacheSkew time.Duration
	// LastUsedThrottle bounds last_used_at writes (default 1m).
	LastUsedThrottle time.Duration
}

func (c Config) withDefaults() Config {
	if c.UIReturnURL == "" {
		c.UIReturnURL = "/settings/git"
	}
	if c.StateTTL <= 0 {
		c.StateTTL = 10 * time.Minute
	}
	if c.AccessCacheSkew <= 0 {
		c.AccessCacheSkew = time.Minute
	}
	if c.LastUsedThrottle <= 0 {
		c.LastUsedThrottle = time.Minute
	}
	return c
}

type cachedAccess struct {
	token  string
	expiry time.Time
}

// Service orchestrates user git connections.
type Service struct {
	db        *db.DB
	store     *Store
	audit     *audit.Store
	cipher    *Cipher
	providers map[string]Provider
	state     *StateManager
	cfg       Config

	now func() time.Time

	mu       sync.Mutex
	cache    map[string]cachedAccess
	lastUsed map[string]time.Time
	sf       singleflight.Group
}

// NewService builds the service. stateKey is the HMAC key for OAuth states.
func NewService(d *db.DB, store *Store, auditStore *audit.Store, cipher *Cipher, providers map[string]Provider, stateKey []byte, cfg Config) (*Service, error) {
	if d == nil || store == nil || auditStore == nil || cipher == nil {
		return nil, errors.New("usergit: db, store, audit store and cipher are required")
	}
	cfg = cfg.withDefaults()
	sm, err := NewStateManager(stateKey, cfg.StateTTL)
	if err != nil {
		return nil, err
	}
	if providers == nil {
		providers = map[string]Provider{}
	}
	return &Service{
		db: d, store: store, audit: auditStore, cipher: cipher,
		providers: providers, state: sm, cfg: cfg,
		now:      time.Now,
		cache:    map[string]cachedAccess{},
		lastUsed: map[string]time.Time{},
	}, nil
}

// UIReturnURL is the browser return target after the OAuth callback.
func (s *Service) UIReturnURL() string { return s.cfg.UIReturnURL }

func (s *Service) provider(name string) (Provider, error) {
	p, ok := s.providers[name]
	if !ok {
		return nil, ErrUnknownProvider
	}
	return p, nil
}

func connectionAAD(id string) string { return "user_git_connections:" + id }

// List returns the caller's own connections (metadata only).
func (s *Service) List(ctx context.Context, orgID, userSub string) ([]Connection, error) {
	return s.store.ListByUser(ctx, s.db.Pool, orgID, userSub)
}

// BeginAuthorize starts the OAuth flow and returns the provider consent
// URL the browser is redirected to.
func (s *Service) BeginAuthorize(ctx context.Context, orgID, userSub, provider, apiBase string) (string, error) {
	p, err := s.provider(provider)
	if err != nil {
		return "", err
	}
	if !p.Configured() {
		return "", ErrProviderNotEnabled
	}
	verifier, err := NewCodeVerifier()
	if err != nil {
		return "", err
	}
	state, err := s.state.Issue(orgID, userSub, provider, apiBase, verifier)
	if err != nil {
		return "", err
	}
	url, err := p.AuthorizeURL(state, CodeChallengeS256(verifier), apiBase)
	if err != nil {
		return "", err
	}
	return url, nil
}

// CompleteAuthorize validates the state, exchanges the code, persists the
// encrypted refresh token (reconnect replaces the row), and audits.
func (s *Service) CompleteAuthorize(ctx context.Context, actor, state, code string) (*Connection, error) {
	payload, err := s.state.Validate(state)
	if err != nil {
		return nil, err
	}
	if payload.UserSub != actor {
		return nil, fmt.Errorf("%w: state bound to a different user", ErrStateInvalid)
	}
	if code == "" {
		return nil, fmt.Errorf("%w: missing authorization code", ErrInvalidInput)
	}
	p, err := s.provider(payload.Provider)
	if err != nil {
		return nil, err
	}
	grant, err := p.Exchange(ctx, code, payload.CodeVerifier, payload.APIBase)
	if err != nil {
		return nil, fmt.Errorf("usergit: exchange: %w", err)
	}
	if grant.RefreshToken == "" {
		return nil, errors.New("usergit: provider returned no refresh token; enable expiring user tokens on the app")
	}
	id := "ugc:" + uuid.NewString()
	refreshEnc, dekEnc, err := s.cipher.Encrypt([]byte(grant.RefreshToken), connectionAAD(id))
	if err != nil {
		return nil, err
	}
	row := &EncryptedRow{
		Connection: Connection{
			ID:            id,
			OrgID:         payload.OrgID,
			UserSub:       payload.UserSub,
			Provider:      payload.Provider,
			ProviderLogin: grant.ProviderLogin,
			Scopes:        grant.Scopes,
			APIBase:       payload.APIBase,
		},
		RefreshTokenEnc: refreshEnc,
		DEKEnc:          dekEnc,
	}
	if err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.UpsertEncrypted(ctx, tx, row); err != nil {
			return err
		}
		return s.recordEvent(ctx, tx, payload.OrgID, actor, "user_git.connected",
			types.EventUserGitConnected, row.ID, payload.UserSub, payload.Provider)
	}); err != nil {
		return nil, err
	}
	s.dropCache(id)
	c := row.Connection
	return &c, nil
}

// Disconnect revokes the provider grant (best-effort) and deletes the row.
// The stored refresh token is decrypted before the delete so a key issue
// cannot silently destroy a connection (same discipline as the credential
// vault); if decryption succeeds, revocation failures never block the
// delete.
func (s *Service) Disconnect(ctx context.Context, actor, orgID, userSub, provider string) error {
	p, err := s.provider(provider)
	if err != nil {
		return err
	}
	row, err := s.store.GetEncrypted(ctx, s.db.Pool, orgID, userSub, provider)
	if err != nil {
		return err
	}
	refresh, err := s.cipher.Decrypt(row.RefreshTokenEnc, row.DEKEnc, connectionAAD(row.ID))
	if err != nil {
		return fmt.Errorf("usergit: decrypt before disconnect: %w", err)
	}
	refreshToken := string(refresh)
	defer Zero(refresh)
	// Best-effort revocation: mint a fresh access token, then delete the
	// grant. Any failure here still proceeds to the delete.
	if grant, err := p.Refresh(ctx, refreshToken, row.APIBase); err == nil && grant.AccessToken != "" {
		_ = p.Revoke(ctx, grant.AccessToken, row.APIBase)
	}
	if err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.Delete(ctx, tx, orgID, userSub, provider); err != nil {
			return err
		}
		return s.recordEvent(ctx, tx, orgID, actor, "user_git.disconnected",
			types.EventUserGitDisconnected, row.ID, userSub, provider)
	}); err != nil {
		return err
	}
	s.dropCache(row.ID)
	return nil
}

// AccessToken returns a valid access token for the caller's connection,
// refreshing (single-flighted per connection) when the cached token is
// missing or near expiry. This is the seam W5's git resolver consumes.
func (s *Service) AccessToken(ctx context.Context, orgID, userSub, provider string) (string, error) {
	row, err := s.store.GetEncrypted(ctx, s.db.Pool, orgID, userSub, provider)
	if err != nil {
		return "", err
	}
	if tok, ok := s.cachedToken(row.ID); ok {
		s.touchLastUsed(ctx, row.ID)
		return tok, nil
	}
	v, err, _ := s.sf.Do(row.ID, func() (any, error) {
		if tok, ok := s.cachedToken(row.ID); ok {
			return tok, nil
		}
		return s.refresh(ctx, row)
	})
	if err != nil {
		return "", err
	}
	s.touchLastUsed(ctx, row.ID)
	return v.(string), nil
}

// refresh decrypts the stored refresh token, rotates it with the provider,
// persists the rotated token BEFORE the new access token is used, and
// caches the access token in memory. A rejected refresh token is treated
// as a replay: the connection is wiped and a compromise event emitted.
func (s *Service) refresh(ctx context.Context, row *EncryptedRow) (string, error) {
	p, err := s.provider(row.Provider)
	if err != nil {
		return "", err
	}
	refresh, err := s.cipher.Decrypt(row.RefreshTokenEnc, row.DEKEnc, connectionAAD(row.ID))
	if err != nil {
		return "", fmt.Errorf("usergit: decrypt refresh token: %w", err)
	}
	defer Zero(refresh)
	grant, err := p.Refresh(ctx, string(refresh), row.APIBase)
	if errors.Is(err, ErrGrantInvalid) {
		s.compromise(ctx, row)
		return "", ErrConnectionCompromised
	}
	if err != nil {
		return "", fmt.Errorf("usergit: refresh: %w", err)
	}
	if grant.RefreshToken != "" {
		// Persist the rotated refresh token before the new access token is
		// ever handed out: losing it would strand the connection (the old
		// token is already invalidated provider-side).
		refreshEnc, dekEnc, err := s.cipher.Encrypt([]byte(grant.RefreshToken), connectionAAD(row.ID))
		if err != nil {
			return "", err
		}
		if err := s.store.UpdateRefreshToken(ctx, s.db.Pool, row.ID, refreshEnc, dekEnc); err != nil {
			return "", fmt.Errorf("usergit: persist rotated refresh token: %w", err)
		}
	}
	expiry := grant.AccessExpiry
	if expiry.IsZero() {
		expiry = s.now().Add(time.Hour)
	}
	s.mu.Lock()
	s.cache[row.ID] = cachedAccess{token: grant.AccessToken, expiry: expiry}
	s.mu.Unlock()
	return grant.AccessToken, nil
}

// compromise wipes a connection after a refresh-token replay and emits the
// compromise audit/outbox event. Best-effort: the caller still gets
// ErrConnectionCompromised even if the wipe fails (logged by the caller's
// error path; never silently retried with the same token).
func (s *Service) compromise(ctx context.Context, row *EncryptedRow) {
	s.dropCache(row.ID)
	_ = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.Delete(ctx, tx, row.OrgID, row.UserSub, row.Provider); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		return s.recordEvent(ctx, tx, row.OrgID, row.UserSub, "user_git.compromised",
			types.EventUserGitCompromised, row.ID, row.UserSub, row.Provider)
	})
}

func (s *Service) cachedToken(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.cache[id]
	if !ok || s.now().Add(s.cfg.AccessCacheSkew).After(c.expiry) {
		return "", false
	}
	return c.token, true
}

func (s *Service) dropCache(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.cache, id)
	delete(s.lastUsed, id)
}

// touchLastUsed throttles last_used_at writes to one per LastUsedThrottle.
func (s *Service) touchLastUsed(ctx context.Context, id string) {
	s.mu.Lock()
	last, ok := s.lastUsed[id]
	if ok && s.now().Sub(last) < s.cfg.LastUsedThrottle {
		s.mu.Unlock()
		return
	}
	s.lastUsed[id] = s.now()
	s.mu.Unlock()
	_ = s.store.TouchLastUsed(ctx, s.db.Pool, id)
}

// recordEvent appends the audit row and outbox event inside tx.
func (s *Service) recordEvent(ctx context.Context, tx pgx.Tx, orgID, actor, action, eventType, connID, userSub, provider string) error {
	if err := s.audit.Record(ctx, tx, &types.AuditEvent{
		OrgID:      orgID,
		Actor:      actor,
		Action:     action,
		ObjectType: "user_git_connection",
		ObjectID:   connID,
	}); err != nil {
		return err
	}
	return audit.AppendOutbox(ctx, tx, orgID, eventType, types.UserGitPayload{
		OrgID:        orgID,
		UserSub:      userSub,
		Provider:     provider,
		ConnectionID: connID,
	})
}
