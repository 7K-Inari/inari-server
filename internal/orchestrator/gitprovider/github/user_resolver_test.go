package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
)

type fakeTokens struct{ tok string }

func (f fakeTokens) AccessToken(context.Context, string, string, string) (string, error) {
	return f.tok, nil
}

type eventSink struct {
	mu     sync.Mutex
	events []ResolvedEvent
}

func (s *eventSink) add(_ context.Context, ev ResolvedEvent) {
	s.mu.Lock()
	s.events = append(s.events, ev)
	s.mu.Unlock()
}

func (s *eventSink) all() []ResolvedEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ResolvedEvent(nil), s.events...)
}

func lookupConn(conn *Connection, err error) LookupConnectionFunc {
	return func(context.Context, string, string, string) (*Connection, error) {
		return conn, err
	}
}

func TestForUserNoConnectionFailsClosed(t *testing.T) {
	sink := &eventSink{}
	r, err := NewUserResolver(UserResolverConfig{
		Tokens: fakeTokens{}, Lookup: lookupConn(nil, ErrConnectionNotFound), OnResolved: sink.add,
	})
	if err != nil {
		t.Fatal(err)
	}
	p, info, err := r.ForUser(context.Background(), "org:1", "user:1")
	if p != nil || info != nil {
		t.Fatalf("expected nil provider/info, got %v %v", p, info)
	}
	var nc *ErrNoConnection
	if !errors.As(err, &nc) {
		t.Fatalf("err = %v, want ErrNoConnection", err)
	}
	if strings.Contains(err.Error(), "user-tok") {
		t.Fatal("error must never carry token material")
	}
	evs := sink.all()
	if len(evs) != 1 || evs[0].Result != "not_connected" || evs[0].AuthModel != gitprovider.AuthModelUser {
		t.Fatalf("events = %+v", evs)
	}
}

func TestForUserResolvesAndAttributes(t *testing.T) {
	var authz string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	conn := &Connection{ID: "ugc:1", Provider: "github", ProviderLogin: "octocat", APIBase: srv.URL}
	r, err := NewUserResolver(UserResolverConfig{
		Tokens: fakeTokens{tok: "user-tok"}, Lookup: lookupConn(conn, nil),
		AllowedAPIBases: []string{srv.URL},
	})
	if err != nil {
		t.Fatal(err)
	}
	p, info, err := r.ForUser(context.Background(), "org:1", "user:1")
	if err != nil {
		t.Fatal(err)
	}
	if info.Model != gitprovider.AuthModelUser || info.ConnectionID != "ugc:1" ||
		info.UserSub != "user:1" || info.ProviderLogin != "octocat" || info.APIBase != srv.URL {
		t.Fatalf("info = %+v", info)
	}
	if _, err := p.ReadFile(context.Background(), "octocat/state", "main", "x"); err != nil {
		t.Fatal(err)
	}
	if authz != "Bearer user-tok" {
		t.Fatalf("Authorization = %q", authz)
	}
}

func TestForUserDefaultAPIBaseNeedsNoAllowlist(t *testing.T) {
	r, err := NewUserResolver(UserResolverConfig{
		Tokens: fakeTokens{}, Lookup: lookupConn(&Connection{ID: "ugc:1", ProviderLogin: "octocat"}, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, info, err := r.ForUser(context.Background(), "org:1", "user:1")
	if err != nil {
		t.Fatal(err)
	}
	if info.APIBase != "https://api.github.com" {
		t.Fatalf("APIBase = %q", info.APIBase)
	}
}

func TestForUserAPIBaseAllowlist(t *testing.T) {
	cases := []struct {
		name    string
		allow   []string
		apiBase string
		wantErr bool
	}{
		{"allowlisted ghe", []string{"https://ghe.corp.example/api/v3"}, "https://ghe.corp.example/api/v3", false},
		{"not allowlisted", nil, "https://ghe.corp.example/api/v3", true},
		{"http non-loopback", []string{"http://ghe.corp.example/api/v3"}, "http://ghe.corp.example/api/v3", true},
		{"garbage", nil, "://bad", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewUserResolver(UserResolverConfig{
				Tokens: fakeTokens{}, Lookup: lookupConn(&Connection{ID: "ugc:1", ProviderLogin: "o", APIBase: tc.apiBase}, nil),
				AllowedAPIBases: tc.allow,
			})
			if tc.name == "http non-loopback" {
				if err == nil {
					t.Fatal("non-https allowlist entry must be rejected at construction")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = r.ForUser(context.Background(), "org:1", "user:1")
			var na *ErrAPIBaseNotAllowed
			if tc.wantErr && !errors.As(err, &na) {
				t.Fatalf("err = %v, want ErrAPIBaseNotAllowed", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestForUserTokenRejectedMapsToTypedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"message": "bad credentials"})
	}))
	t.Cleanup(srv.Close)
	conn := &Connection{ID: "ugc:9", Provider: "github", ProviderLogin: "octocat", APIBase: srv.URL}
	r, err := NewUserResolver(UserResolverConfig{
		Tokens: fakeTokens{tok: "user-tok"}, Lookup: lookupConn(conn, nil), AllowedAPIBases: []string{srv.URL},
	})
	if err != nil {
		t.Fatal(err)
	}
	p, _, err := r.ForUser(context.Background(), "org:1", "user:1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.ReadFile(context.Background(), "octocat/state", "main", "x")
	var inv *ErrUserTokenInvalid
	if !errors.As(err, &inv) {
		t.Fatalf("err = %v, want ErrUserTokenInvalid", err)
	}
	if inv.ConnectionID != "ugc:9" {
		t.Fatalf("ConnectionID = %q", inv.ConnectionID)
	}
	if strings.Contains(err.Error(), "user-tok") {
		t.Fatal("typed error must never carry token material")
	}
}

func TestResolverForUserDelegation(t *testing.T) {
	// Unwired: fails closed.
	r := &Resolver{}
	if _, _, err := r.ForUser(context.Background(), "org:1", "user:1"); !errors.Is(err, gitprovider.ErrUserModelUnsupported) {
		t.Fatalf("err = %v, want ErrUserModelUnsupported", err)
	}
	// Wired: delegates.
	ur, err := NewUserResolver(UserResolverConfig{
		Tokens: fakeTokens{}, Lookup: lookupConn(nil, ErrConnectionNotFound),
	})
	if err != nil {
		t.Fatal(err)
	}
	r.User = ur
	var nc *ErrNoConnection
	if _, _, err := r.ForUser(context.Background(), "org:1", "user:1"); !errors.As(err, &nc) {
		t.Fatalf("err = %v, want ErrNoConnection", err)
	}
}

func TestNewUserResolverRequiresDeps(t *testing.T) {
	if _, err := NewUserResolver(UserResolverConfig{}); err == nil {
		t.Fatal("want error for missing deps")
	}
}

func TestResolvedEventHasNoTokenMaterial(t *testing.T) {
	sink := &eventSink{}
	conn := &Connection{ID: "ugc:1", Provider: "github", ProviderLogin: "octocat"}
	r, err := NewUserResolver(UserResolverConfig{
		Tokens: fakeTokens{tok: "secret-access-token"}, Lookup: lookupConn(conn, nil), OnResolved: sink.add,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.ForUser(context.Background(), "org:1", "user:1"); err != nil {
		t.Fatal(err)
	}
	for _, ev := range sink.all() {
		if strings.Contains(fmt.Sprintf("%+v", ev), "secret-access-token") {
			t.Fatalf("event leaks token: %+v", ev)
		}
	}
}
