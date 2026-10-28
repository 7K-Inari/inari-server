package gitprovider

import (
	"context"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestStaticResolverReturnsSameProvider(t *testing.T) {
	fake := NewFake()
	r := StaticResolver{P: fake}
	p, info, err := r.ForTenant(context.Background(), &types.TenantGitConfig{OrgID: "org:1", Repo: "acme/acme-inari-state"})
	if err != nil {
		t.Fatal(err)
	}
	if p != Provider(fake) {
		t.Fatalf("want the wrapped provider, got %T", p)
	}
	if info == nil || info.Model != AuthModelStatic {
		t.Fatalf("want static auth info, got %+v", info)
	}
}

func TestStaticResolverForUserFailsClosed(t *testing.T) {
	r := StaticResolver{P: NewFake()}
	p, info, err := r.ForUser(context.Background(), "org:1", "user:1")
	if p != nil || info != nil {
		t.Fatalf("static resolver must never impersonate a user: %v %v", p, info)
	}
	if err != ErrUserModelUnsupported {
		t.Fatalf("err = %v, want ErrUserModelUnsupported", err)
	}
}

func TestStaticResolverIgnoresConfig(t *testing.T) {
	fake := NewFake()
	r := StaticResolver{P: fake}
	p, _, err := r.ForTenant(context.Background(), nil)
	if err != nil || p != Provider(fake) {
		t.Fatalf("nil config must still resolve the static provider: %v %v", p, err)
	}
}

// PerRepo addresses arbitrary repos (Feature A team repos like
// "myorg/team-a-gitops"), not just *-inari-state names. The platform-owned
// constraint is unchanged: resolution always goes through the wrapped
// Resolver with only the repo set (model A — no BYO, no user identity).
func TestPerRepoArbitraryRepoNames(t *testing.T) {
	fake := NewFake()
	pr := PerRepo{R: StaticResolver{P: fake}}
	ctx := context.Background()
	for _, repo := range []string{"myorg/team-a-gitops", "other-org/platform-baseline", "acme/acme-inari-state"} {
		if _, err := pr.EnsureRepo(ctx, repo); err != nil {
			t.Fatalf("EnsureRepo(%q): %v", repo, err)
		}
		if _, err := pr.CommitFiles(ctx, repo, "main", []File{{Path: "README.md", Content: []byte("hi")}}, "init"); err != nil {
			t.Fatalf("CommitFiles(%q): %v", repo, err)
		}
		got, err := pr.ReadFile(ctx, repo, "main", "README.md")
		if err != nil || got != "hi" {
			t.Fatalf("ReadFile(%q) = %q, %v", repo, got, err)
		}
	}
}

// PerRepo never carries a BYO override or org identity: the wrapped
// resolver always sees a bare repo (platform-app-only constraint).
func TestPerRepoNeverCarriesBYO(t *testing.T) {
	rec := &recordingResolver{provider: NewFake(), info: &AuthInfo{Model: AuthModelPlatform}}
	pr := PerRepo{R: rec}
	if _, err := pr.EnsureRepo(context.Background(), "myorg/team-a-gitops"); err != nil {
		t.Fatal(err)
	}
	if rec.lastCfg == nil || rec.lastCfg.GitHubApp != nil || rec.lastCfg.OrgID != "" {
		t.Fatalf("PerRepo must resolve platform-only, got %+v", rec.lastCfg)
	}
	if rec.lastCfg.Repo != "myorg/team-a-gitops" {
		t.Fatalf("repo = %q", rec.lastCfg.Repo)
	}
}
