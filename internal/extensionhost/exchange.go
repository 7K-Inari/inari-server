// RFC 8693 token exchange against Keycloak (plan §5.8): the caller's access
// token is exchanged per request for a token scoped to the extension's
// declared downstream audience, acting as the extension's own client
// (ext-<name>). Exchanged tokens live only in an in-memory cache keyed by
// (user sub, extension, audience) with TTL min(token exp, 60s); they are
// never persisted and never logged.
package extensionhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	tokenExchangeGrantType   = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeAccessToken     = "urn:ietf:params:oauth:token-type:access_token"
	exchangeCacheMaxTTL      = 60 * time.Second
	exchangeHTTPTimeout      = 10 * time.Second
	defaultExchangeTokenTTL  = 60 * time.Second
)

// ErrExchangeDenied: Keycloak refused the exchange (4xx — e.g. the user has
// no downstream permission). Maps to 403 downstream_permission_denied.
var ErrExchangeDenied = errors.New("extensionhost: token exchange denied")

// ErrExchangeUnavailable: the exchange endpoint failed (network, 5xx).
// Maps to 502.
var ErrExchangeUnavailable = errors.New("extensionhost: token exchange unavailable")

// ErrExchangeAudienceNotAllowed: the requested audience is outside the
// extension's declared allowlist (audience separation invariant).
var ErrExchangeAudienceNotAllowed = errors.New("extensionhost: exchange audience not allowed")

// TokenExchanger exchanges a subject token for a downstream-scoped token.
// extensionName is the registry name (globally unique; also determines the
// Keycloak client ext-<name>). Implementations must never persist or log
// token material.
type TokenExchanger interface {
	Exchange(ctx context.Context, extensionName, subjectToken, audience string, scopes []string) (token string, err error)
}

// ClientSecretResolver resolves the current secret of a confidential Keycloak
// client (implemented by tenancy.KeycloakAdmin via the admin API; the secret
// is read at exchange time, never stored on the extension row).
type ClientSecretResolver interface {
	ClientSecret(ctx context.Context, clientID string) (string, error)
}

type exchangeCacheEntry struct {
	token  string
	expiry time.Time
}

type exchangeCacheKey struct {
	subjectHash string
	extensionID string
	audience    string
}

// KeycloakExchanger implements RFC 8693 token exchange against the realm's
// token endpoint, authenticating as the extension's own client.
type KeycloakExchanger struct {
	tokenURL   string
	secrets    ClientSecretResolver
	http       *http.Client
	now        func() time.Time
	subjectKey func(subjectToken string) string // derives sub; injectable for tests

	mu    sync.Mutex
	cache map[exchangeCacheKey]exchangeCacheEntry
}

// NewKeycloakExchanger targets the realm token endpoint derived from the OIDC
// issuer URL ({issuer}/protocol/openid-connect/token).
func NewKeycloakExchanger(issuerURL string, secrets ClientSecretResolver) *KeycloakExchanger {
	return &KeycloakExchanger{
		tokenURL: strings.TrimRight(issuerURL, "/") + "/protocol/openid-connect/token",
		secrets:  secrets,
		http:     &http.Client{Timeout: exchangeHTTPTimeout},
		now:      time.Now,
		cache:    map[exchangeCacheKey]exchangeCacheEntry{},
	}
}

// WithSubjectKey overrides how the cache key subject is derived from the
// subject token (default: the token itself is hashed; tests inject a fixed
// derivation). Returning "" disables caching for that call.
func (e *KeycloakExchanger) WithSubjectKey(fn func(subjectToken string) string) *KeycloakExchanger {
	e.subjectKey = fn
	return e
}

// Exchange performs (or returns a cached) token exchange. Per-request: the
// cache TTL is capped at 60s, so tokens are re-exchanged at least that often.
func (e *KeycloakExchanger) Exchange(ctx context.Context, extensionName, subjectToken, audience string, scopes []string) (string, error) {
	if subjectToken == "" {
		return "", fmt.Errorf("%w: empty subject token", ErrExchangeDenied)
	}
	key := exchangeCacheKey{extensionID: extensionName, audience: audience}
	if e.subjectKey != nil {
		key.subjectHash = e.subjectKey(subjectToken)
	} else {
		key.subjectHash = hashToken(subjectToken)
	}
	if key.subjectHash != "" {
		if tok, ok := e.cached(key); ok {
			return tok, nil
		}
	}
	token, expiresIn, err := e.exchange(ctx, extensionName, subjectToken, audience, scopes)
	if err != nil {
		return "", err
	}
	if key.subjectHash != "" {
		ttl := time.Duration(expiresIn) * time.Second
		if ttl <= 0 {
			ttl = defaultExchangeTokenTTL
		}
		ttl = min(ttl, exchangeCacheMaxTTL)
		e.store(key, token, e.now().Add(ttl))
	}
	return token, nil
}

func (e *KeycloakExchanger) cached(key exchangeCacheKey) (string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ent, ok := e.cache[key]
	if !ok {
		return "", false
	}
	if !e.now().Before(ent.expiry) {
		delete(e.cache, key)
		return "", false
	}
	return ent.token, true
}

func (e *KeycloakExchanger) store(key exchangeCacheKey, token string, expiry time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	// Lazy sweep: bound the map by dropping expired entries on write.
	for k, v := range e.cache {
		if !e.now().Before(v.expiry) {
			delete(e.cache, k)
		}
	}
	e.cache[key] = exchangeCacheEntry{token: token, expiry: expiry}
}

// exchange issues the RFC 8693 request as the extension's client. The subject
// token and the exchanged token never appear in errors or logs.
func (e *KeycloakExchanger) exchange(ctx context.Context, extensionName, subjectToken, audience string, scopes []string) (token string, expiresIn int, err error) {
	clientID := ExtensionClientID(extensionName)
	secret, err := e.secrets.ClientSecret(ctx, clientID)
	if err != nil {
		return "", 0, fmt.Errorf("%w: client credentials: %v", ErrExchangeUnavailable, redactErr(err))
	}
	form := url.Values{
		"grant_type":           {tokenExchangeGrantType},
		"client_id":            {clientID},
		"client_secret":        {secret},
		"subject_token":        {subjectToken},
		"subject_token_type":   {tokenTypeAccessToken},
		"requested_token_type": {tokenTypeAccessToken},
	}
	if audience != "" {
		form.Set("audience", audience)
	}
	if len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := e.http.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %v", ErrExchangeUnavailable, redactErr(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return "", 0, fmt.Errorf("%w: status %d", ErrExchangeDenied, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("%w: status %d", ErrExchangeUnavailable, resp.StatusCode)
	}
	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", 0, fmt.Errorf("%w: decode: %v", ErrExchangeUnavailable, redactErr(err))
	}
	if body.AccessToken == "" {
		return "", 0, fmt.Errorf("%w: empty access token in response", ErrExchangeUnavailable)
	}
	return body.AccessToken, body.ExpiresIn, nil
}

// hashToken derives the cache-key subject from a subject token without
// retaining token material.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// redactErr strips anything that could embed token material from transport
// errors (url.Error echoes the request URL; form bodies are never in URLs,
// but defense in depth: only the error type is surfaced).
func redactErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err.Error()
	}
	return "request failed"
}
