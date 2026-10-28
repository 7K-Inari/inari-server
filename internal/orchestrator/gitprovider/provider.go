// Package gitprovider abstracts the git backend behind a provider interface
// (plan §11.2/§12.1-2): GitHub first via GitHub App credentials (never
// PATs); fakes drive tests. Rendered desired state lands in the
// platform-owned <tenant>-inari-state repository.
package gitprovider

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// File is one file to write at a repo-relative path.
type File struct {
	Path    string
	Content []byte
}

// Result reports what a write produced.
type Result struct {
	CommitSHA string
	PRURL     string // set for pull-request writes
}

// WebhookConfig describes one provider-side webhook registration (parent
// plan §9 risk #1: the ingress endpoint that closes the PR-merge gap).
type WebhookConfig struct {
	// URL is the public ingress endpoint deliveries POST to.
	URL string
	// Secret is the per-repo HMAC shared secret (write-only on the
	// provider side; the server keeps the envelope-encrypted copy).
	Secret string
	// Events are the provider's event names, e.g. "pull_request", "push".
	Events []string
}

// Provider writes desired state to a git host.
type Provider interface {
	// EnsureRepo makes sure the state repository exists and returns its
	// canonical clone URL (each provider owns its URL semantics — e.g.
	// GitLab can return the create-repo API's http_url_to_repo).
	EnsureRepo(ctx context.Context, repo string) (cloneURL string, err error)
	// CommitFiles writes files directly to a branch.
	CommitFiles(ctx context.Context, repo, branch string, files []File, message string) (*Result, error)
	// DeleteFiles removes files from a branch. Deleting a path that does
	// not exist is a no-op (idempotent retries).
	DeleteFiles(ctx context.Context, repo, branch string, paths []string, message string) (*Result, error)
	// OpenPR writes files on a fresh branch and opens a pull request against
	// base. Returns the PR URL.
	OpenPR(ctx context.Context, repo, base, title, body string, files []File) (*Result, error)
	// ReadFile returns the file content at path on branch, or
	// ("", nil) when it does not exist.
	ReadFile(ctx context.Context, repo, branch, path string) (string, error)
	// EnsureWebhook idempotently registers (or updates) the repo's webhook
	// pointing at cfg.URL, returning the provider-side hook ID ("" when
	// the provider has no hook concept). Idempotency means "no duplicate
	// hooks for the same URL", not "no API writes": hook secrets are
	// write-only, so an existing hook is always re-configured (which is
	// also what makes secret rotation work).
	EnsureWebhook(ctx context.Context, repo string, cfg WebhookConfig) (hookID string, err error)
}

// Fake is an in-memory Provider for tests and local dev (no git host).
type Fake struct {
	mu    sync.Mutex
	repos map[string]*fakeRepo
	// PRs records every OpenPR call for assertions.
	PRs []PRRecord
	// Deletions records every DeleteFiles call for assertions.
	Deletions []DeleteRecord
	// Webhooks records every EnsureWebhook call for assertions.
	Webhooks []WebhookRecord
}

// WebhookRecord captures one EnsureWebhook invocation.
type WebhookRecord struct {
	Repo   string
	Config WebhookConfig
}

// DeleteRecord captures one DeleteFiles invocation.
type DeleteRecord struct {
	Repo, Branch, Message string
	Paths                 []string
}

// PRRecord captures one OpenPR invocation.
type PRRecord struct {
	Repo, Base, Title, Body string
	Files                   []File
}

type fakeRepo struct {
	branches map[string]map[string]string // branch → path → content
}

func NewFake() *Fake {
	return &Fake{repos: map[string]*fakeRepo{}}
}

func (f *Fake) EnsureRepo(_ context.Context, repo string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.repos[repo]; !ok {
		f.repos[repo] = &fakeRepo{branches: map[string]map[string]string{}}
	}
	return fmt.Sprintf("https://fake.git/%s.git", repo), nil
}

func (f *Fake) CommitFiles(_ context.Context, repo, branch string, files []File, _ string) (*Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, err := f.repo(repo)
	if err != nil {
		return nil, err
	}
	if r.branches[branch] == nil {
		r.branches[branch] = map[string]string{}
	}
	for _, file := range files {
		r.branches[branch][file.Path] = string(file.Content)
	}
	return &Result{CommitSHA: fakeSHA(repo, branch, len(r.branches[branch]))}, nil
}

func (f *Fake) OpenPR(_ context.Context, repo, base, title, body string, files []File) (*Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.repo(repo); err != nil {
		return nil, err
	}
	f.PRs = append(f.PRs, PRRecord{Repo: repo, Base: base, Title: title, Body: body, Files: files})
	n := len(f.PRs)
	return &Result{
		CommitSHA: fakeSHA(repo, "pr", n),
		PRURL:     fmt.Sprintf("https://fake.git/%s/pull/%d", repo, n),
	}, nil
}

func (f *Fake) DeleteFiles(_ context.Context, repo, branch string, paths []string, message string) (*Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, err := f.repo(repo)
	if err != nil {
		return nil, err
	}
	for _, p := range paths {
		delete(r.branches[branch], p)
	}
	f.Deletions = append(f.Deletions, DeleteRecord{Repo: repo, Branch: branch, Message: message, Paths: paths})
	return &Result{CommitSHA: fakeSHA(repo, branch, len(r.branches[branch]))}, nil
}

// EnsureWebhook records the call and returns a stable per-(repo,URL) hook
// ID (idempotent re-registration keeps the same hook).
func (f *Fake) EnsureWebhook(_ context.Context, repo string, cfg WebhookConfig) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, w := range f.Webhooks {
		if w.Repo == repo && w.Config.URL == cfg.URL {
			f.Webhooks = append(f.Webhooks, WebhookRecord{Repo: repo, Config: cfg})
			return fmt.Sprintf("fake-hook-%s-%x", repo, fnv(repo, cfg.URL)), nil
		}
	}
	f.Webhooks = append(f.Webhooks, WebhookRecord{Repo: repo, Config: cfg})
	return fmt.Sprintf("fake-hook-%s-%x", repo, fnv(repo, cfg.URL)), nil
}

func (f *Fake) ReadFile(_ context.Context, repo, branch, path string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, err := f.repo(repo)
	if err != nil {
		return "", err
	}
	return r.branches[branch][path], nil
}

func (f *Fake) repo(name string) (*fakeRepo, error) {
	r, ok := f.repos[name]
	if !ok {
		return nil, fmt.Errorf("gitprovider: repo %q does not exist", name)
	}
	return r, nil
}

// Files lists all files of a repo branch (test assertion helper).
func (f *Fake) Files(repo, branch string) map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]string{}
	r, ok := f.repos[repo]
	if !ok {
		return out
	}
	paths := make([]string, 0, len(r.branches[branch]))
	for p := range r.branches[branch] {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		out[p] = r.branches[branch][p]
	}
	return out
}

func fakeSHA(repo, branch string, n int) string {
	return fmt.Sprintf("%x", fnv(repo, branch, n))
}

func fnv(parts ...any) uint64 {
	h := uint64(1469598103934665603)
	for _, p := range parts {
		for _, b := range fmt.Sprint(p) {
			h ^= uint64(b)
			h *= 1099511628211
		}
	}
	return h
}
