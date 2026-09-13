package gitprovider

import (
	"context"
	"strings"
	"testing"
)

func TestLocalProviderLifecycle(t *testing.T) {
	root := t.TempDir()
	p := NewLocal(root)
	ctx := context.Background()

	url, err := p.EnsureRepo(ctx, "acme-inari-state")
	if err != nil {
		t.Fatalf("EnsureRepo: %v", err)
	}
	if url == "" {
		t.Error("EnsureRepo returned no clone URL")
	}
	// Idempotent.
	if _, err := p.EnsureRepo(ctx, "acme-inari-state"); err != nil {
		t.Fatalf("EnsureRepo second call: %v", err)
	}

	res, err := p.CommitFiles(ctx, "acme-inari-state", "main",
		[]File{{Path: "baseline/rbac/clusterroles.yaml", Content: []byte("kind: ClusterRole")}}, "seed")
	if err != nil {
		t.Fatalf("CommitFiles: %v", err)
	}
	if res.CommitSHA == "" {
		t.Error("no commit SHA")
	}

	got, err := p.ReadFile(ctx, "acme-inari-state", "main", "baseline/rbac/clusterroles.yaml")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if got != "kind: ClusterRole" {
		t.Errorf("ReadFile = %q", got)
	}
	if missing, err := p.ReadFile(ctx, "acme-inari-state", "main", "nope.yaml"); err != nil || missing != "" {
		t.Errorf("missing file = %q, %v; want empty, nil", missing, err)
	}

	// Update + no-change idempotency: committing identical content must
	// not advance HEAD.
	res2, err := p.CommitFiles(ctx, "acme-inari-state", "main",
		[]File{{Path: "baseline/rbac/clusterroles.yaml", Content: []byte("kind: ClusterRole")}}, "same")
	if err != nil {
		t.Fatal(err)
	}
	if res2.CommitSHA != res.CommitSHA {
		t.Errorf("unchanged content created a new commit (%s → %s)", res.CommitSHA, res2.CommitSHA)
	}
	res3, err := p.CommitFiles(ctx, "acme-inari-state", "main",
		[]File{{Path: "baseline/rbac/clusterroles.yaml", Content: []byte("kind: ClusterRole\nrules: []")}}, "update")
	if err != nil {
		t.Fatal(err)
	}
	if res3.CommitSHA == res.CommitSHA {
		t.Error("changed content did not advance HEAD")
	}

	if _, err := p.DeleteFiles(ctx, "acme-inari-state", "main", []string{"baseline/rbac/clusterroles.yaml"}, "prune"); err != nil {
		t.Fatalf("DeleteFiles: %v", err)
	}
	if got, _ := p.ReadFile(ctx, "acme-inari-state", "main", "baseline/rbac/clusterroles.yaml"); got != "" {
		t.Errorf("file still present after delete: %q", got)
	}
	// Deleting a missing path is a no-op.
	if _, err := p.DeleteFiles(ctx, "acme-inari-state", "main", []string{"baseline/rbac/clusterroles.yaml"}, "prune"); err != nil {
		t.Fatalf("DeleteFiles idempotent: %v", err)
	}
}

func TestLocalProviderOpenPR(t *testing.T) {
	p := NewLocal(t.TempDir())
	ctx := context.Background()
	if _, err := p.EnsureRepo(ctx, "repo"); err != nil {
		t.Fatal(err)
	}
	res, err := p.OpenPR(ctx, "repo", "main", "title", "body",
		[]File{{Path: "a.yaml", Content: []byte("x")}})
	if err != nil {
		t.Fatalf("OpenPR: %v", err)
	}
	if res.PRURL == "" {
		t.Error("OpenPR returned no URL")
	}
	// Local git has no PRs: the change lands on a side branch, main untouched.
	if got, _ := p.ReadFile(ctx, "repo", "main", "a.yaml"); got != "" {
		t.Errorf("PR content leaked onto main: %q", got)
	}
}

func TestLocalProviderMissingRepo(t *testing.T) {
	p := NewLocal(t.TempDir())
	if _, err := p.CommitFiles(context.Background(), "ghost", "main", []File{{Path: "a", Content: []byte("b")}}, "m"); err == nil {
		t.Fatal("expected error for missing repo")
	}
}

func TestLocalProviderRejectsEscapes(t *testing.T) {
	p := NewLocal(t.TempDir())
	if _, err := p.EnsureRepo(context.Background(), "../escape"); err == nil {
		t.Fatal("expected path-escape rejection")
	}
	if _, err := p.EnsureRepo(context.Background(), strings.Repeat("a/", 5)+"ok"); err != nil {
		t.Fatalf("nested owner/name should be fine: %v", err)
	}
}
