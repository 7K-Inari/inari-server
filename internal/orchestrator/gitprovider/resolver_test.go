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
