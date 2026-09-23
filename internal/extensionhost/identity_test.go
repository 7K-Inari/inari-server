package extensionhost

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"connectrpc.com/connect"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

func TestExtensionClientID(t *testing.T) {
	if got := ExtensionClientID("argocd"); got != "ext-argocd" {
		t.Fatalf("ExtensionClientID = %q", got)
	}
}

func TestExtensionClientSpec(t *testing.T) {
	spec := ExtensionClientSpec("argocd", "inari-extension-gateway")
	if spec.ClientID != "ext-argocd" || spec.ClientType != tenancy.ClientTypeService {
		t.Fatalf("spec = %+v", spec)
	}
	if len(spec.Audiences) != 1 || spec.Audiences[0] != "inari-extension-gateway" {
		t.Fatalf("audiences = %v", spec.Audiences)
	}
	if len(spec.RedirectURIs) != 0 {
		t.Fatalf("service client must have no redirect URIs: %v", spec.RedirectURIs)
	}
}

type stubValidator struct {
	id  *authn.Identity
	err error
}

func (s *stubValidator) Validate(context.Context, string) (*authn.Identity, error) {
	return s.id, s.err
}

type fakeByClientID struct {
	ext *types.Extension
	err error
	got string
}

func (f *fakeByClientID) GetByClientID(_ context.Context, clientID string) (*types.Extension, error) {
	f.got = clientID
	return f.ext, f.err
}

func bearer(h http.Header, tok string) http.Header {
	h.Set("Authorization", "Bearer "+tok)
	return h
}

func TestTunnelAuthenticator(t *testing.T) {
	readyExt := &types.Extension{ID: "extension:1", Name: "argocd", OrgID: "org:1",
		ClientID: "ext-argocd", State: types.ExtensionStateReady}

	t.Run("missing bearer", func(t *testing.T) {
		a := NewTunnelAuthenticator(&fakeByClientID{}, &stubValidator{})
		_, err := a.AuthenticateExtension(context.Background(), http.Header{})
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		a := NewTunnelAuthenticator(&fakeByClientID{}, &stubValidator{err: errors.New("bad token")})
		_, err := a.AuthenticateExtension(context.Background(), bearer(http.Header{}, "x"))
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("no authorized party", func(t *testing.T) {
		a := NewTunnelAuthenticator(&fakeByClientID{}, &stubValidator{id: &authn.Identity{Subject: "svc"}})
		_, err := a.AuthenticateExtension(context.Background(), bearer(http.Header{}, "x"))
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("unknown client", func(t *testing.T) {
		a := NewTunnelAuthenticator(&fakeByClientID{err: ErrNotFound}, &stubValidator{
			id: &authn.Identity{Subject: "svc", AuthorizedParty: "ext-ghost"}})
		_, err := a.AuthenticateExtension(context.Background(), bearer(http.Header{}, "x"))
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("extension not ready", func(t *testing.T) {
		degraded := *readyExt
		degraded.State = types.ExtensionStateDegraded
		a := NewTunnelAuthenticator(&fakeByClientID{ext: &degraded}, &stubValidator{
			id: &authn.Identity{Subject: "svc", AuthorizedParty: "ext-argocd"}})
		_, err := a.AuthenticateExtension(context.Background(), bearer(http.Header{}, "x"))
		if connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("ok resolves extension by azp", func(t *testing.T) {
		byID := &fakeByClientID{ext: readyExt}
		a := NewTunnelAuthenticator(byID, &stubValidator{
			id: &authn.Identity{Subject: "svc", AuthorizedParty: "ext-argocd"}})
		ext, err := a.AuthenticateExtension(context.Background(), bearer(http.Header{}, "x"))
		if err != nil {
			t.Fatal(err)
		}
		if ext.ID != readyExt.ID || byID.got != "ext-argocd" {
			t.Fatalf("ext = %+v, lookup = %q", ext, byID.got)
		}
	})
}
