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

// Provider writes desired state to a git host.
type Provider interface {
	// EnsureRepo makes sure the state repository exists.
	EnsureRepo(ctx context.Context, repo string) error
	// CommitFiles writes files directly to a branch.
	CommitFiles(ctx context.Context, repo, branch string, files []File, message string) (*Result, error)
	// OpenPR writes files on a fresh branch and opens a pull request against
	// base. Returns the PR URL.
	OpenPR(ctx context.Context, repo, base, title, body string, files []File) (*Result, error)
	// ReadFile returns the file content at path on branch, or
	// ("", nil) when it does not exist.
	ReadFile(ctx context.Context, repo, branch, path string) (string, error)
}

// Fake is an in-memory Provider for tests and local dev (no git host).
type Fake struct {
	mu    sync.Mutex
	repos map[string]*fakeRepo
	// PRs records every OpenPR call for assertions.
	PRs []PRRecord
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

func (f *Fake) EnsureRepo(_ context.Context, repo string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.repos[repo]; !ok {
		f.repos[repo] = &fakeRepo{branches: map[string]map[string]string{}}
	}
	return nil
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
