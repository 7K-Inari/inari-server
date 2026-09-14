package gitprovider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage"
)

// Local is a filesystem-backed Provider for dev/e2e (INARI_GIT_PROVIDER=
// local): repositories are bare git repos under a root directory, written
// with go-git plumbing only (tree/blob/commit objects built directly) —
// no git binary required anywhere, distroless-safe. It produces REAL
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
	r, entries, parent, err := l.load(repo, branch)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		h, err := storeBlob(r.Storer, f.Content)
		if err != nil {
			return nil, err
		}
		entries[f.Path] = object.TreeEntry{Name: f.Path, Mode: filemode.Regular, Hash: h}
	}
	return l.storeCommit(r, branch, entries, parent, message)
}

// DeleteFiles implements Provider; deleting a missing path is a no-op.
func (l *Local) DeleteFiles(_ context.Context, repo, branch string, paths []string, message string) (*Result, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, entries, parent, err := l.load(repo, branch)
	if err != nil {
		return nil, err
	}
	for _, p := range paths {
		delete(entries, p) // missing files are already gone
	}
	return l.storeCommit(r, branch, entries, parent, message)
}

// OpenPR implements Provider: local git has no pull requests, so the
// change lands on a side branch and the returned URL names it.
func (l *Local) OpenPR(_ context.Context, repo, base, title, _ string, files []File) (*Result, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	branch := "inari/" + sanitizeBranch(title)
	r, entries, parent, err := l.load(repo, base)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		h, err := storeBlob(r.Storer, f.Content)
		if err != nil {
			return nil, err
		}
		entries[f.Path] = object.TreeEntry{Name: f.Path, Mode: filemode.Regular, Hash: h}
	}
	res, err := l.storeCommit(r, branch, entries, parent, title)
	if err != nil {
		return nil, err
	}
	res.PRURL = "local://" + repo + "/pull/" + branch
	return res, nil
}

// ReadFile implements Provider; a missing path (or an unborn branch)
// reads as ("", nil).
func (l *Local) ReadFile(_ context.Context, repo, branch, path string) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, err := l.openBare(repo)
	if err != nil {
		return "", err
	}
	commit, err := headCommit(r, branch)
	if errors.Is(err, plumbing.ErrReferenceNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	f, err := commit.File(path)
	if errors.Is(err, object.ErrFileNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return f.Contents()
}

// openBare opens the bare repo (erroring when it does not exist).
func (l *Local) openBare(repo string) (*git.Repository, error) {
	path, err := l.repoPath(repo)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("gitprovider local: stat repo %q: %w", repo, err)
	}
	r, err := git.PlainOpen(path)
	if err != nil {
		return nil, fmt.Errorf("gitprovider local: open %s: %w", repo, err)
	}
	return r, nil
}

// headCommit resolves refs/heads/<branch>; an unborn branch reports
// plumbing.ErrReferenceNotFound.
func headCommit(r *git.Repository, branch string) (*object.Commit, error) {
	ref, err := r.Reference(plumbing.NewBranchReferenceName(branch), true)
	if err != nil {
		return nil, err
	}
	return r.CommitObject(ref.Hash())
}

// load opens the repo and flattens the branch's tree into path→entry
// (empty map + no parent for an unborn branch).
func (l *Local) load(repo, branch string) (*git.Repository, map[string]object.TreeEntry, *object.Commit, error) {
	r, err := l.openBare(repo)
	if err != nil {
		return nil, nil, nil, err
	}
	entries := map[string]object.TreeEntry{}
	parent, err := headCommit(r, branch)
	if errors.Is(err, plumbing.ErrReferenceNotFound) {
		return r, entries, nil, nil
	}
	if err != nil {
		return nil, nil, nil, err
	}
	tree, err := parent.Tree()
	if err != nil {
		return nil, nil, nil, err
	}
	walker := object.NewTreeWalker(tree, true, nil)
	defer walker.Close()
	for {
		name, entry, err := walker.Next()
		if err != nil {
			break
		}
		if entry.Mode == filemode.Dir {
			continue // recursive walker lists subtrees themselves
		}
		entries[name] = object.TreeEntry{Name: name, Mode: entry.Mode, Hash: entry.Hash}
	}
	return r, entries, parent, nil
}

// storeCommit writes the flattened entries as a new tree + commit on
// branch. Identical content produces no new commit (HEAD SHA returned).
func (l *Local) storeCommit(r *git.Repository, branch string, entries map[string]object.TreeEntry, parent *object.Commit, message string) (*Result, error) {
	treeHash, err := storeTree(r.Storer, entries, "")
	if err != nil {
		return nil, err
	}
	var parents []plumbing.Hash
	if parent != nil {
		if parent.TreeHash == treeHash {
			return &Result{CommitSHA: parent.Hash.String()}, nil
		}
		parents = []plumbing.Hash{parent.Hash}
	}
	sig := object.Signature{Name: "inari-server", Email: "inari-server@inari.local", When: time.Now()}
	commitHash, err := storeObject(r.Storer, &object.Commit{
		Message:      message,
		Author:       sig,
		Committer:    sig,
		TreeHash:     treeHash,
		ParentHashes: parents,
	})
	if err != nil {
		return nil, err
	}
	ref := plumbing.NewHashReference(plumbing.NewBranchReferenceName(branch), commitHash)
	if err := r.Storer.SetReference(ref); err != nil {
		return nil, fmt.Errorf("gitprovider local: update %s: %w", branch, err)
	}
	return &Result{CommitSHA: commitHash.String()}, nil
}

// storeBlob writes one blob object.
func storeBlob(st storage.Storer, content []byte) (plumbing.Hash, error) {
	obj := st.NewEncodedObject()
	obj.SetType(plumbing.BlobObject)
	obj.SetSize(int64(len(content)))
	w, err := obj.Writer()
	if err != nil {
		return plumbing.ZeroHash, err
	}
	if _, err := w.Write(content); err != nil {
		_ = w.Close()
		return plumbing.ZeroHash, err
	}
	if err := w.Close(); err != nil {
		return plumbing.ZeroHash, err
	}
	return st.SetEncodedObject(obj)
}

// storeObject encodes and stores one git object.
func storeObject(st storage.Storer, o object.Object) (plumbing.Hash, error) {
	obj := st.NewEncodedObject()
	if err := o.Encode(obj); err != nil {
		return plumbing.ZeroHash, err
	}
	return st.SetEncodedObject(obj)
}

// storeTree writes the flattened path→entry map as nested tree objects
// under prefix, returning the root tree hash. Empty maps encode the
// well-known empty tree.
func storeTree(st storage.Storer, entries map[string]object.TreeEntry, prefix string) (plumbing.Hash, error) {
	var treeEntries []object.TreeEntry
	subdirs := map[string]map[string]object.TreeEntry{}
	for p, e := range entries {
		rest := strings.TrimPrefix(p, prefix)
		if i := strings.Index(rest, "/"); i >= 0 {
			dir := rest[:i]
			if subdirs[dir] == nil {
				subdirs[dir] = map[string]object.TreeEntry{}
			}
			subdirs[dir][p] = e
			continue
		}
		treeEntries = append(treeEntries, object.TreeEntry{Name: rest, Mode: e.Mode, Hash: e.Hash})
	}
	for dir, sub := range subdirs {
		h, err := storeTree(st, sub, prefix+dir+"/")
		if err != nil {
			return plumbing.ZeroHash, err
		}
		treeEntries = append(treeEntries, object.TreeEntry{Name: dir, Mode: filemode.Dir, Hash: h})
	}
	// Git orders tree entries by name, directories as name+"/".
	sort.Slice(treeEntries, func(i, j int) bool {
		a, b := treeEntries[i], treeEntries[j]
		an, bn := a.Name, b.Name
		if a.Mode == filemode.Dir {
			an += "/"
		}
		if b.Mode == filemode.Dir {
			bn += "/"
		}
		return an < bn
	})
	return storeObject(st, &object.Tree{Entries: treeEntries})
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
