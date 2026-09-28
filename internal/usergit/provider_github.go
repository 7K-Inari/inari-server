// GitHub user-OAuth provider (W4): a dedicated GitHub App user flow with
// expiring user-to-server tokens and refresh-token rotation — distinct from
// the platform/BYO GitHub Apps (installation tokens) in
// internal/orchestrator/gitprovider. Supports GHE via an allowlisted
// apiBase. Token material never appears in errors.
package usergit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultGitHubAPIBase = "https://api.github.com"

// GitHubConfig configures the dedicated user-OAuth GitHub App.
type GitHubConfig struct {
	ClientID     string
	ClientSecret string
	// CallbackURL is the public callback URL registered on the app
	// (redirect_uri sent to GitHub).
	CallbackURL string
	// Scopes requested at authorize time (e.g. "repo read:user"); empty
	// requests the app-configured default scopes.
	Scopes string
	// AllowedAPIBases allowlists GHE API base URLs (e.g.
	// "https://ghe.corp.example/api/v3"); empty permits only github.com.
	AllowedAPIBases []string
	HTTPClient      *http.Client
}

// GitHubProvider implements Provider against the GitHub App user OAuth flow.
type GitHubProvider struct {
	cfg       GitHubConfig
	allowlist map[string]bool
	http      *http.Client
}

func NewGitHubProvider(cfg GitHubConfig) (*GitHubProvider, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("usergit: github user app client id and secret required")
	}
	allow := map[string]bool{}
	for _, base := range cfg.AllowedAPIBases {
		u, err := url.Parse(base)
		if err != nil || u.Host == "" || (u.Scheme != "https" && !isLoopbackHTTP(u)) {
			return nil, fmt.Errorf("usergit: invalid allowed api base %q (https URL required)", base)
		}
		allow[u.Host] = true
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	return &GitHubProvider{cfg: cfg, allowlist: allow, http: hc}, nil
}

func (p *GitHubProvider) Name() string { return "github" }

// Configured reports whether the provider holds working app credentials.
// The constructor requires both, so this is always true today; the field
// check keeps the contract honest if construction ever relaxes.
func (p *GitHubProvider) Configured() bool {
	return p.cfg.ClientID != "" && p.cfg.ClientSecret != ""
}

// isLoopbackHTTP permits http api bases only for loopback hosts (dev/tests).
func isLoopbackHTTP(u *url.URL) bool {
	if u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// resolveEndpoints validates apiBase (SSRF guard) and returns the API base
// and web origin. "" means github.com.
func (p *GitHubProvider) resolveEndpoints(apiBase string) (api, web string, err error) {
	if apiBase == "" {
		return defaultGitHubAPIBase, "https://github.com", nil
	}
	u, err := url.Parse(apiBase)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !isLoopbackHTTP(u)) {
		return "", "", fmt.Errorf("%w: api base must be an https URL", ErrInvalidInput)
	}
	if !p.allowlist[u.Host] {
		return "", "", fmt.Errorf("%w: api base host not allowlisted", ErrInvalidInput)
	}
	origin := u.Scheme + "://" + u.Host
	return strings.TrimRight(apiBase, "/"), origin, nil
}

func (p *GitHubProvider) AuthorizeURL(state, codeChallenge, apiBase string) (string, error) {
	_, web, err := p.resolveEndpoints(apiBase)
	if err != nil {
		return "", err
	}
	q := url.Values{
		"client_id":             {p.cfg.ClientID},
		"redirect_uri":          {p.cfg.CallbackURL},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}
	if p.cfg.Scopes != "" {
		q.Set("scope", p.cfg.Scopes)
	}
	return web + "/login/oauth/authorize?" + q.Encode(), nil
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// tokenError maps GitHub OAuth error codes. bad_verification_code and
// bad_refresh_token mean the presented code/refresh token was rejected —
// for a refresh that means the token was rotated away or revoked, i.e. a
// possible replay, surfaced as ErrGrantInvalid.
type tokenError struct{ code string }

func (e *tokenError) Error() string { return "usergit: github oauth error: " + e.code }

// grantInvalidCodes are OAuth error codes indicating the presented grant is
// permanently invalid (rotated/revoked/wrong), never transient.
var grantInvalidCodes = map[string]bool{
	"bad_verification_code":        true,
	"bad_refresh_token":            true,
	"incorrect_client_credentials": true,
}

func (p *GitHubProvider) tokenRequest(ctx context.Context, web string, form url.Values) (*tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, web+"/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("usergit: token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := p.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("usergit: token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("usergit: token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("usergit: token endpoint status %d", resp.StatusCode)
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("usergit: token response decode: %w", err)
	}
	if tr.Error != "" {
		if grantInvalidCodes[tr.Error] {
			return nil, ErrGrantInvalid
		}
		return nil, &tokenError{code: tr.Error}
	}
	if tr.AccessToken == "" {
		return nil, errors.New("usergit: token response missing access token")
	}
	return &tr, nil
}

func (p *GitHubProvider) Exchange(ctx context.Context, code, codeVerifier, apiBase string) (*TokenGrant, error) {
	api, web, err := p.resolveEndpoints(apiBase)
	if err != nil {
		return nil, err
	}
	tr, err := p.tokenRequest(ctx, web, url.Values{
		"client_id":     {p.cfg.ClientID},
		"client_secret": {p.cfg.ClientSecret},
		"code":          {code},
		"redirect_uri":  {p.cfg.CallbackURL},
		"grant_type":    {"authorization_code"},
		"code_verifier": {codeVerifier},
	})
	if err != nil {
		return nil, err
	}
	grant := &TokenGrant{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		Scopes:       tr.Scope,
	}
	if tr.ExpiresIn > 0 {
		grant.AccessExpiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	login, err := p.providerLogin(ctx, api, grant.AccessToken)
	if err != nil {
		return nil, err
	}
	grant.ProviderLogin = login
	return grant, nil
}

func (p *GitHubProvider) Refresh(ctx context.Context, refreshToken, apiBase string) (*TokenGrant, error) {
	api, web, err := p.resolveEndpoints(apiBase)
	if err != nil {
		return nil, err
	}
	tr, err := p.tokenRequest(ctx, web, url.Values{
		"client_id":     {p.cfg.ClientID},
		"client_secret": {p.cfg.ClientSecret},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	})
	if err != nil {
		return nil, err
	}
	grant := &TokenGrant{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken, // empty when the app does not rotate
		Scopes:       tr.Scope,
	}
	if tr.ExpiresIn > 0 {
		grant.AccessExpiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	login, err := p.providerLogin(ctx, api, grant.AccessToken)
	if err != nil {
		return nil, err
	}
	grant.ProviderLogin = login
	return grant, nil
}

// Revoke deletes the app's grant for the user (revokes the whole
// authorization, not just the token). 404 means already revoked.
func (p *GitHubProvider) Revoke(ctx context.Context, accessToken, apiBase string) error {
	api, _, err := p.resolveEndpoints(apiBase)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"access_token": accessToken})
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		api+"/applications/"+p.cfg.ClientID+"/grant", strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("usergit: revoke request: %w", err)
	}
	req.SetBasicAuth(p.cfg.ClientID, p.cfg.ClientSecret)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := p.http.Do(req)
	if err != nil {
		return fmt.Errorf("usergit: revoke: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	return fmt.Errorf("usergit: revoke: status %d", resp.StatusCode)
}

func (p *GitHubProvider) providerLogin(ctx context.Context, api, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api+"/user", nil)
	if err != nil {
		return "", fmt.Errorf("usergit: user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := p.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("usergit: user lookup: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", fmt.Errorf("usergit: user lookup: status %d", resp.StatusCode)
	}
	var u struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return "", fmt.Errorf("usergit: user decode: %w", err)
	}
	if u.Login == "" {
		return "", errors.New("usergit: user lookup returned no login")
	}
	return u.Login, nil
}
