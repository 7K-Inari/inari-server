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
