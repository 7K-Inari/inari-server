package gitprovider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/storage/memory"
)

// Local is a filesystem-backed Provider for dev/e2e (INARI_GIT_PROVIDER=
// local): repositories are bare git repos under a root directory, written
// with go-git (no git binary required, distroless-safe). It produces REAL
// commits — unlike Fake — so an external syncer (the e2e harness standing
// in for the tenant-local ArgoCD) can clone and apply the desired state.
type Local struct {
	root string
	mu   sync.Mutex
}

// NewLocal returns a Provider storing bare repos under root.
func NewLocal(root string) *Local { return &Local{root: root} }

// repoPath maps "owner/name" (or bare "name") onto root safely.
func (l *Local) repoPath(repo string) (string, error) {
	if repo == "" || strings.HasPrefix(repo, "/") || strings.Contains(repo, "\\") {
		return "", fmt.Errorf("gitprovider local: invalid repo %q", repo)
	}
	for _, part := range strings.Split(repo, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("gitprovider local: invalid repo %q", repo)
		}
	}
	return filepath.Join(l.root, repo+".git"), nil
}

// EnsureRepo implements Provider.
func (l *Local) EnsureRepo(_ context.Context, repo string) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	path, err := l.repoPath(repo)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(path); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			// EACCES etc.: do NOT treat the repo as existing — the next
			// read would fail with a misleading "does not exist".
			return "", fmt.Errorf("gitprovider local: stat %s: %w", repo, err)
		}
		if err := os.MkdirAll(path, 0o755); err != nil {
			return "", err
		}
		r, err := git.PlainInit(path, true)
		if err != nil {
			return "", fmt.Errorf("gitprovider local: init %s: %w", repo, err)
		}
		// PlainInit points HEAD at refs/heads/master; the platform
		// convention is main.
		if err := r.Storer.SetReference(
			plumbing.NewSymbolicReference(plumbing.HEAD, plumbing.NewBranchReferenceName("main"))); err != nil {
			return "", err
		}
	}
	return "file://" + path, nil
}

// CommitFiles implements Provider. Identical content produces no new
// commit (HEAD SHA returned unchanged), keeping materialization idempotent.
func (l *Local) CommitFiles(_ context.Context, repo, branch string, files []File, message string) (*Result, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, w, err := l.checkout(repo, branch)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if err := writeBillyFile(w.Filesystem, f.Path, f.Content); err != nil {
			return nil, err
		}
	}
	return l.commit(r, w, branch, message)
}

// DeleteFiles implements Provider; deleting a missing path is a no-op.
func (l *Local) DeleteFiles(_ context.Context, repo, branch string, paths []string, message string) (*Result, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, w, err := l.checkout(repo, branch)
	if err != nil {
		return nil, err
	}
	for _, p := range paths {
		_ = w.Filesystem.Remove(p) // missing files are already gone
	}
	return l.commit(r, w, branch, message)
}

// OpenPR implements Provider: local git has no pull requests, so the
// change lands on a side branch and the returned URL names it.
func (l *Local) OpenPR(_ context.Context, repo, base, title, _ string, files []File) (*Result, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	branch := "inari/" + sanitizeBranch(title)
	r, w, err := l.checkout(repo, base)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if err := writeBillyFile(w.Filesystem, f.Path, f.Content); err != nil {
			return nil, err
		}
	}
	res, err := l.commit(r, w, branch, title)
	if err != nil {
		return nil, err
	}
	res.PRURL = "local://" + repo + "/pull/" + branch
	return res, nil
}

// ReadFile implements Provider; a missing path reads as ("", nil).
func (l *Local) ReadFile(_ context.Context, repo, branch, path string) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, _, err := l.open(repo)
	if err != nil {
		if errors.Is(err, errNoHead) {
			return "", nil
		}
		return "", err
	}
	ref, err := r.Reference(plumbing.NewBranchReferenceName(branch), true)
	if err != nil {
		return "", nil // branch not created yet: nothing committed
	}
	commit, err := r.CommitObject(ref.Hash())
	if err != nil {
		return "", err
	}
	tree, err := commit.Tree()
	if err != nil {
		return "", err
	}
	f, err := tree.File(path)
	if err != nil {
		return "", nil
	}
	return f.Contents()
}

var errNoHead = errors.New("gitprovider local: repo has no commits")

// open returns the in-memory clone of the named repo.
func (l *Local) open(repo string) (*git.Repository, *git.Worktree, error) {
	path, err := l.repoPath(repo)
	if err != nil {
		return nil, nil, err
	}
	if _, err := os.Stat(path); err != nil {
		return nil, nil, fmt.Errorf("gitprovider local: stat repo %q: %w", repo, err)
	}
	r, err := git.Clone(memory.NewStorage(), memfs.New(), &git.CloneOptions{URL: path})
	if errors.Is(err, transport.ErrEmptyRemoteRepository) || errors.Is(err, plumbing.ErrReferenceNotFound) {
		// Empty bare repo: start a fresh in-memory repo and treat the bare
		// one as the push target.
		r, err = git.Init(memory.NewStorage(), memfs.New())
		if err != nil {
			return nil, nil, err
		}
		if _, err := r.CreateRemote(&config.RemoteConfig{Name: "origin", URLs: []string{path}}); err != nil {
			return nil, nil, err
		}
		w, err := mustWorktree(r)
		if err != nil {
			return nil, nil, err
		}
		return r, w, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("gitprovider local: clone %s: %w", repo, err)
	}
	w, err := mustWorktree(r)
	if err != nil {
		return nil, nil, err
	}
	return r, w, nil
}

// checkout opens the repo and makes sure branch is checked out (created
// from HEAD when missing).
func (l *Local) checkout(repo, branch string) (*git.Repository, *git.Worktree, error) {
	r, w, err := l.open(repo)
	if err != nil {
		return nil, nil, err
	}
	if _, err := r.Head(); errors.Is(err, plumbing.ErrReferenceNotFound) {
		// No commits yet: point HEAD at the target branch so the first
		// commit lands there (go-git cannot Checkout-Create without HEAD).
		if err := r.Storer.SetReference(
			plumbing.NewSymbolicReference(plumbing.HEAD, plumbing.NewBranchReferenceName(branch))); err != nil {
			return nil, nil, err
		}
		return r, w, nil
	}
	_, branchErr := r.Reference(plumbing.NewBranchReferenceName(branch), true)
	if err := w.Checkout(&git.CheckoutOptions{
		Branch: plumbing.NewBranchReferenceName(branch),
		Create: errors.Is(branchErr, plumbing.ErrReferenceNotFound),
	}); err != nil {
		return nil, nil, fmt.Errorf("gitprovider local: checkout %s: %w", branch, err)
	}
	return r, w, nil
}

// commit stages everything (including deletions), commits when content
// changed, and pushes to the bare repo.
func (l *Local) commit(r *git.Repository, w *git.Worktree, branch, message string) (*Result, error) {
	if err := w.AddWithOptions(&git.AddOptions{All: true, Path: "."}); err != nil {
		return nil, err
	}
	status, err := w.Status()
	if err != nil {
		return nil, err
	}
	head, headErr := r.Head()
	if status.IsClean() && headErr == nil {
		return &Result{CommitSHA: head.Hash().String()}, nil
	}
	hash, err := w.Commit(message, &git.CommitOptions{
		Author: &object.Signature{Name: "inari-server", Email: "inari-server@inari.local", When: time.Now()},
	})
	if err != nil {
		return nil, fmt.Errorf("gitprovider local: commit: %w", err)
	}
	// Push from the in-memory clone to the bare repo. The remote already
	// exists for clones; the empty-repo path created it explicitly.
	remotes, err := r.Remotes()
	if err != nil {
		return nil, err
	}
	if len(remotes) == 0 {
		return nil, fmt.Errorf("gitprovider local: no origin remote")
	}
	spec := config.RefSpec(fmt.Sprintf("%s:%s", plumbing.NewBranchReferenceName(branch), plumbing.NewBranchReferenceName(branch)))
	err = r.Push(&git.PushOptions{RemoteName: "origin", RefSpecs: []config.RefSpec{spec}})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return nil, fmt.Errorf("gitprovider local: push: %w", err)
	}
	return &Result{CommitSHA: hash.String()}, nil
}

func mustWorktree(r *git.Repository) (*git.Worktree, error) {
	w, err := r.Worktree()
	return w, err
}

func writeBillyFile(fs billy.Filesystem, path string, content []byte) error {
	if err := fs.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := fs.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = f.Write(content)
	return err
}

func sanitizeBranch(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "change"
	}
	if len(out) > 48 {
		out = out[:48]
	}
	return out
}
