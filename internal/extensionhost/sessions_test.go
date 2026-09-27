package extensionhost

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/authn"
)

type fakeSessionStore struct {
	sess *UserSession
	err  error
	put  *UserSession
}

func (f *fakeSessionStore) Get(context.Context, string, string, string) (*UserSession, error) {
	return f.sess, f.err
}

func (f *fakeSessionStore) Put(_ context.Context, _, _ string, s *UserSession) error {
	f.put = s
	return nil
}

func (f *fakeSessionStore) Delete(context.Context, string, string, string) error { return nil }

func ssoRequest(t *testing.T, store SessionStore) (ConnectionProvider, ConnectionRequest) {
	p := &ssoSessionProvider{sessions: store}
	req := ConnectionRequest{
		Extension: extWithManifest(t, ""),
		Identity:  &authn.Identity{Subject: "user-1"},
		Declared:  DeclaredAuthMethod{Method: AuthMethodOIDCSSOSession, Audience: "argocd"},
	}
	return p, req
}

func TestSSOSessionProviderHit(t *testing.T) {
	store := &fakeSessionStore{sess: &UserSession{Provider: "argocd", Credential: "sess-tok", Expiry: time.Now().Add(time.Hour)}}
	p, req := ssoRequest(t, store)
	got, err := p.Resolve(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if got.DownstreamToken != "sess-tok" || got.Audience != "argocd" {
		t.Fatalf("got %+v", got)
	}
}

func TestSSOSessionProviderMissRequiresReauth(t *testing.T) {
	p, req := ssoRequest(t, &fakeSessionStore{err: ErrSessionNotFound})
	_, err := p.Resolve(context.Background(), req)
	var re *ErrReauthRequired
	if !errors.As(err, &re) || re.Provider != "argocd" {
		t.Fatalf("got %v, want ErrReauthRequired{argocd}", err)
	}
}

func TestSSOSessionProviderExpiredRequiresReauth(t *testing.T) {
	store := &fakeSessionStore{sess: &UserSession{Provider: "argocd", Credential: "old", Expiry: time.Now().Add(-time.Minute)}}
	p, req := ssoRequest(t, store)
	_, err := p.Resolve(context.Background(), req)
	var re *ErrReauthRequired
	if !errors.As(err, &re) {
		t.Fatalf("got %v", err)
	}
}

func TestSSOSessionProviderNilStoreFailsClosed(t *testing.T) {
	p, req := ssoRequest(t, nil)
	_, err := p.Resolve(context.Background(), req)
	var re *ErrReauthRequired
	if !errors.As(err, &re) {
		t.Fatalf("got %v, want ErrReauthRequired", err)
	}
}

func TestSSOSessionProviderEmptyCredentialRequiresReauth(t *testing.T) {
	store := &fakeSessionStore{sess: &UserSession{Provider: "argocd"}}
	p, req := ssoRequest(t, store)
	_, err := p.Resolve(context.Background(), req)
	var re *ErrReauthRequired
	if !errors.As(err, &re) {
		t.Fatalf("got %v", err)
	}
}
