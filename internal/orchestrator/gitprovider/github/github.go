// Package github implements gitprovider.Provider against the GitHub REST
// API, authenticated as a GitHub App installation (plan §12.1/2 — App
// credentials only, never PATs). The App private key is delivered to the
// control plane via ESO (mounted file); the installation token is minted
// on demand and cached briefly in memory.
package github

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
)

// Provider writes desired state to GitHub as an App installation.
type Provider struct {
	apiBase        string
	appID          int64
	installationID int64
	key            *rsa.PrivateKey
	http           *http.Client

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

// Config carries GitHub App credentials (never a PAT).
type Config struct {
	AppID          int64
	InstallationID int64
	// PrivateKeyFile is the PEM path (delivered via ESO, §12.2).
	PrivateKeyFile string
	// APIBase overrides https://api.github.com (tests).
	APIBase string
}

// APIError is a failed GitHub API call. Body is truncated (log-size guard).
type APIError struct {
	Method string
	Path   string
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("gitprovider github: %s %s: status %d: %s", e.Method, e.Path, e.Status, e.Body)
}

// indicatesRevoked reports whether a 401/403 plausibly means the app's
// credentials were suspended/revoked (vs. a permission-scope or rate-limit
// rejection, whose message GitHub includes in the body).
func (e *APIError) indicatesRevoked() bool {
	b := strings.ToLower(e.Body)
	switch {
	case strings.Contains(b, "rate limit"):
		return false
	case strings.Contains(b, "permission"):
		return false
	case strings.Contains(b, "workflow"):
		return false
	case strings.Contains(b, "not installed"):
		return false
	}
	return true
}

func New(cfg Config) (*Provider, error) {
	raw, err := os.ReadFile(cfg.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("gitprovider github: read app key: %w", err)
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(raw)
	if err != nil {
		return nil, fmt.Errorf("gitprovider github: parse app key: %w", err)
	}
	return NewWithKey(cfg.AppID, cfg.InstallationID, key, cfg.APIBase), nil
}

// NewWithKey builds a Provider from an already-parsed App private key
// (used by the per-tenant resolver; key bytes are loaded once and reused).
func NewWithKey(appID, installationID int64, key *rsa.PrivateKey, apiBase string) *Provider {
	base := apiBase
	if base == "" {
		base = "https://api.github.com"
	}
	return &Provider{
		apiBase:        strings.TrimSuffix(base, "/"),
		appID:          appID,
		installationID: installationID,
		key:            key,
		http:           &http.Client{Timeout: 30 * time.Second},
	}
}

// signAppJWT signs a short-lived App JWT (RS256, §12.1).
func signAppJWT(appID int64, key *rsa.PrivateKey) (string, error) {
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now.Add(-30 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute)),
		Issuer:    fmt.Sprint(appID),
	})
	return tok.SignedString(key)
}

// appJWT signs a short-lived App JWT (RS256, §12.1).
func (p *Provider) appJWT() (string, error) {
	return signAppJWT(p.appID, p.key)
}

// installationToken mints (and caches) an installation access token.
func (p *Provider) installationToken(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.token != "" && time.Now().Before(p.tokenExp.Add(-time.Minute)) {
		return p.token, nil
	}
	jwtTok, err := p.appJWT()
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", p.apiBase, p.installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+jwtTok)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := p.http.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		if len(body) > 512 {
			body = body[:512]
		}
		return "", &APIError{Method: http.MethodPost, Path: fmt.Sprintf("/app/installations/%d/access_tokens", p.installationID), Status: resp.StatusCode, Body: string(body)}
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	p.token, p.tokenExp = out.Token, out.ExpiresAt
	return p.token, nil
}

// do performs an authenticated API call. body may be nil.
func (p *Provider) do(ctx context.Context, method, path string, body, out any) (int, error) {
	tok, err := p.installationToken(ctx)
	if err != nil {
		return 0, err
	}
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.apiBase+path, rdr)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/vnd.github+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode >= 400 {
		body := string(raw)
		if len(body) > 512 {
			body = body[:512]
		}
		return resp.StatusCode, &APIError{Method: method, Path: path, Status: resp.StatusCode, Body: body}
	}
	if out != nil && len(raw) > 0 {
		return resp.StatusCode, json.Unmarshal(raw, out)
	}
	return resp.StatusCode, nil
}

// splitRepo splits "owner/name" (optionally host-prefixed URL).
func splitRepo(repo string) (string, string, error) {
	repo = strings.TrimPrefix(repo, "https://github.com/")
	repo = strings.TrimSuffix(repo, ".git")
	parts := strings.Split(repo, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("gitprovider github: invalid repo %q (want owner/name)", repo)
	}
	return parts[0], parts[1], nil
}

func (p *Provider) EnsureRepo(ctx context.Context, repo string) (string, error) {
	owner, name, err := splitRepo(repo)
	if err != nil {
		return "", err
	}
	status, err := p.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s", owner, name), nil, nil)
	if status == http.StatusNotFound {
		return "", fmt.Errorf("gitprovider github: repo %s not found; create %s-inari-state via the tenant zone flow", repo, owner)
	}
	if err != nil {
		return "", err
	}
	return p.webBase() + "/" + owner + "/" + name + ".git", nil
}

// webBase derives the clone-URL host from the API base: api.github.com maps
// to github.com; a GitHub Enterprise <host>/api/v3 maps to <host>.
func (p *Provider) webBase() string {
	return webBaseFrom(p.apiBase)
}

func (p *Provider) CommitFiles(ctx context.Context, repo, branch string, files []gitprovider.File, message string) (*gitprovider.Result, error) {
	owner, name, err := splitRepo(repo)
	if err != nil {
		return nil, err
	}
	sha, err := p.commitTree(ctx, owner, name, branch, files, message)
	if err != nil {
		return nil, err
	}
	return &gitprovider.Result{CommitSHA: sha}, nil
}

// headSuffix derives a stable, branch-safe PR head name from the title
// (works for short titles; avoids collisions between different deploys).
func headSuffix(title string) string {
	sum := sha256.Sum256([]byte(title))
	return base64.RawURLEncoding.EncodeToString(sum[:])[:24]
}

func (p *Provider) OpenPR(ctx context.Context, repo, base, title, body string, files []gitprovider.File) (*gitprovider.Result, error) {
	owner, name, err := splitRepo(repo)
	if err != nil {
		return nil, err
	}
	head := "inari/" + headSuffix(title)
	sha, err := p.commitTree(ctx, owner, name, head, files, title)
	if err != nil {
		return nil, err
	}
	var pr struct {
		HTMLURL string `json:"html_url"`
	}
	if _, err := p.do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/%s/pulls", owner, name), map[string]string{
		"title": title, "head": head, "base": base, "body": body,
	}, &pr); err != nil {
		return nil, err
	}
	return &gitprovider.Result{CommitSHA: sha, PRURL: pr.HTMLURL}, nil
}

// DeleteFiles removes paths via a tree whose entries carry a null SHA
// (GitHub tree API deletion semantics). Missing paths are silently ignored
// by the API, so retries are idempotent.
func (p *Provider) DeleteFiles(ctx context.Context, repo, branch string, paths []string, message string) (*gitprovider.Result, error) {
	owner, name, err := splitRepo(repo)
	if err != nil {
		return nil, err
	}
	base := fmt.Sprintf("/repos/%s/%s", owner, name)
	var ref struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if _, err := p.do(ctx, http.MethodGet, base+"/git/ref/heads/"+branch, nil, &ref); err != nil {
		return nil, err
	}
	type treeEntry struct {
		Path string  `json:"path"`
		Mode string  `json:"mode"`
		Type string  `json:"type"`
		SHA  *string `json:"sha"`
	}
	entries := make([]treeEntry, 0, len(paths))
	for _, path := range paths {
		entries = append(entries, treeEntry{Path: path, Mode: "100644", Type: "blob", SHA: nil})
	}
	var tree struct {
		SHA string `json:"sha"`
	}
	if _, err := p.do(ctx, http.MethodPost, base+"/git/trees", map[string]any{
		"base_tree": ref.Object.SHA, "tree": entries,
	}, &tree); err != nil {
		return nil, err
	}
	var commit struct {
		SHA string `json:"sha"`
	}
	if _, err := p.do(ctx, http.MethodPost, base+"/git/commits", map[string]any{
		"message": message, "tree": tree.SHA, "parents": []string{ref.Object.SHA},
	}, &commit); err != nil {
		return nil, err
	}
	if _, err := p.do(ctx, http.MethodPatch, base+"/git/refs/heads/"+branch, map[string]any{
		"sha": commit.SHA, "force": true,
	}, nil); err != nil {
		return nil, err
	}
	return &gitprovider.Result{CommitSHA: commit.SHA}, nil
}

func (p *Provider) ReadFile(ctx context.Context, repo, branch, path string) (string, error) {
	owner, name, err := splitRepo(repo)
	if err != nil {
		return "", err
	}
	var out struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	status, err := p.do(ctx, http.MethodGet,
		fmt.Sprintf("/repos/%s/%s/contents/%s?ref=%s", owner, name, path, branch), nil, &out)
	if status == http.StatusNotFound {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(out.Content, "\n", ""))
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// commitTree creates blobs → tree → commit → ref update on branch.
func (p *Provider) commitTree(ctx context.Context, owner, name, branch string, files []gitprovider.File, message string) (string, error) {
	base := fmt.Sprintf("/repos/%s/%s", owner, name)

	var baseSHA string
	var ref struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	status, err := p.do(ctx, http.MethodGet, base+"/git/ref/heads/"+branch, nil, &ref)
	if err != nil && status != http.StatusNotFound && status != http.StatusConflict {
		return "", err
	}
	if status == http.StatusNotFound || status == http.StatusConflict {
		// Empty repo: GitHub answers 404 (missing ref) or 409 ("Git
		// Repository is empty"). The git-database API (blobs/trees) also 409s
		// while a repo has zero commits, so seed it through the Contents API
		// (which accepts the first commit) and then take the normal path.
		if s, err := p.do(ctx, http.MethodPut, base+"/contents/.inari-init", map[string]any{
			"message": "chore: initialize repository",
			"content":  base64.StdEncoding.EncodeToString([]byte("initialized by inari\n")),
			"branch":   branch,
		}, nil); err != nil && s != http.StatusUnprocessableEntity {
			return "", fmt.Errorf("gitprovider github: seed empty repo: %w", err)
		}
		if _, err := p.do(ctx, http.MethodGet, base+"/git/ref/heads/"+branch, nil, &ref); err != nil {
			return "", err
		}
		baseSHA = ref.Object.SHA
	} else {
		baseSHA = ref.Object.SHA
	}

	type treeEntry struct {
		Path string `json:"path"`
		Mode string `json:"mode"`
		Type string `json:"type"`
		SHA  string `json:"sha"`
	}
	entries := make([]treeEntry, 0, len(files))
	for _, f := range files {
		var blob struct {
			SHA string `json:"sha"`
		}
		if _, err := p.do(ctx, http.MethodPost, base+"/git/blobs", map[string]string{
			"content":  base64.StdEncoding.EncodeToString(f.Content),
			"encoding": "base64",
		}, &blob); err != nil {
			return "", err
		}
		entries = append(entries, treeEntry{Path: f.Path, Mode: "100644", Type: "blob", SHA: blob.SHA})
	}

	treeReq := map[string]any{"tree": entries}
	if baseSHA != "" {
		treeReq["base_tree"] = baseSHA
	}
	var tree struct {
		SHA string `json:"sha"`
	}
	if _, err := p.do(ctx, http.MethodPost, base+"/git/trees", treeReq, &tree); err != nil {
		return "", err
	}

	commitReq := map[string]any{"message": message, "tree": tree.SHA}
	if baseSHA != "" {
		commitReq["parents"] = []string{baseSHA}
	}
	var commit struct {
		SHA string `json:"sha"`
	}
	if _, err := p.do(ctx, http.MethodPost, base+"/git/commits", commitReq, &commit); err != nil {
		return "", err
	}

	if baseSHA == "" {
		_, err = p.do(ctx, http.MethodPost, base+"/git/refs", map[string]string{
			"ref": "refs/heads/" + branch, "sha": commit.SHA,
		}, nil)
	} else {
		_, err = p.do(ctx, http.MethodPatch, base+"/git/refs/heads/"+branch, map[string]any{
			"sha": commit.SHA, "force": true,
		}, nil)
	}
	if err != nil {
		return "", err
	}
	return commit.SHA, nil
}
