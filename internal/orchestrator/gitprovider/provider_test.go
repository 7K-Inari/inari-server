package gitprovider

import (
	"context"
	"testing"
)

func TestFakeProviderFlow(t *testing.T) {
	ctx := context.Background()
	f := NewFake()

	if _, err := f.CommitFiles(ctx, "org/repo", "main", []File{{Path: "a.yaml", Content: []byte("x")}}, "m"); err == nil {
		t.Error("commit to unknown repo should fail")
	}
	if _, err := f.EnsureRepo(ctx, "org/repo"); err != nil {
		t.Fatal(err)
	}
	res, err := f.CommitFiles(ctx, "org/repo", "main", []File{{Path: "a.yaml", Content: []byte("x")}}, "m")
	if err != nil {
		t.Fatal(err)
	}
	if res.CommitSHA == "" || res.PRURL != "" {
		t.Errorf("direct commit result = %+v", res)
	}
	got, err := f.ReadFile(ctx, "org/repo", "main", "a.yaml")
	if err != nil || got != "x" {
		t.Errorf("ReadFile = %q, %v", got, err)
	}

	pr, err := f.OpenPR(ctx, "org/repo", "main", "title", "body", []File{{Path: "b.yaml", Content: []byte("y")}})
	if err != nil {
		t.Fatal(err)
	}
	if pr.PRURL == "" {
		t.Error("OpenPR returned no PR URL")
	}
	if len(f.PRs) != 1 || f.PRs[0].Base != "main" {
		t.Errorf("PRs = %+v", f.PRs)
	}
}

func TestFakeDeleteFiles(t *testing.T) {
	ctx := context.Background()
	f := NewFake()
	if _, err := f.EnsureRepo(ctx, "org/repo"); err != nil {
		t.Fatal(err)
	}
	files := []File{
		{Path: "tenants/acme/a.yaml", Content: []byte("a")},
		{Path: "tenants/acme/b.yaml", Content: []byte("b")},
		{Path: "tenants/other/c.yaml", Content: []byte("c")},
	}
	if _, err := f.CommitFiles(ctx, "org/repo", "main", files, "seed"); err != nil {
		t.Fatal(err)
	}
	res, err := f.DeleteFiles(ctx, "org/repo", "main",
		[]string{"tenants/acme/a.yaml", "tenants/acme/b.yaml", "tenants/acme/missing.yaml"}, "remove acme")
	if err != nil {
		t.Fatal(err)
	}
	if res.CommitSHA == "" {
		t.Error("DeleteFiles returned no commit SHA")
	}
	got := f.Files("org/repo", "main")
	if len(got) != 1 || got["tenants/other/c.yaml"] != "c" {
		t.Errorf("remaining files = %+v", got)
	}
	if len(f.Deletions) != 1 || len(f.Deletions[0].Paths) != 3 || f.Deletions[0].Branch != "main" {
		t.Errorf("Deletions = %+v", f.Deletions)
	}
	if _, err := f.DeleteFiles(ctx, "org/unknown", "main", []string{"x"}, "m"); err == nil {
		t.Error("delete from unknown repo should fail")
	}
}
