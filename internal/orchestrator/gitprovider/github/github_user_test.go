package github

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
)

// userMux serves the fake GitHub API for a model-C provider: only
// "Bearer user-tok" is accepted, and any App token-minting call is a bug.
func userMux(t *testing.T, tokenCalls *atomic.Int32, api http.HandlerFunc) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/access_tokens") {
			if tokenCalls != nil {
				tokenCalls.Add(1)
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Authorization") != "Bearer user-tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		api(w, r)
	})
}

func testUserProvider(t *testing.T, handler http.Handler) *Provider {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewUserProvider(func(context.Context) (string, error) {
		return "user-tok", nil
	}, srv.URL, UserIdentity{Login: "octocat"})
}

func TestUserProviderEnsureRepoExists(t *testing.T) {
	p := testUserProvider(t, userMux(t, nil, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/repos/octocat/state" {
			_ = json.NewEncoder(w).Encode(map[string]any{})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	url, err := p.EnsureRepo(context.Background(), "octocat/state")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(url, "/octocat/state.git") {
		t.Fatalf("url = %q", url)
	}
}

func TestUserProviderEnsureRepoCreatesOwnAccount(t *testing.T) {
	var created atomic.Int32
	var gotBody map[string]any
	p := testUserProvider(t, userMux(t, nil, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodPost && r.URL.Path == "/user/repos":
			created.Add(1)
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	url, err := p.EnsureRepo(context.Background(), "OctoCat/state")
	if err != nil {
		t.Fatal(err)
	}
	if created.Load() != 1 {
		t.Fatalf("created = %d, want 1 (case-insensitive own-account match)", created.Load())
	}
	if gotBody["name"] != "state" || gotBody["private"] != true {
		t.Fatalf("create body = %v", gotBody)
	}
	if !strings.HasSuffix(url, "/OctoCat/state.git") {
		t.Fatalf("url = %q", url)
	}
}

func TestUserProviderEnsureRepoCreatesInOrg(t *testing.T) {
	var path string
	p := testUserProvider(t, userMux(t, nil, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			path = r.URL.Path
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	if _, err := p.EnsureRepo(context.Background(), "acme/state"); err != nil {
		t.Fatal(err)
	}
	if path != "/orgs/acme/repos" {
		t.Fatalf("path = %q", path)
	}
}

func TestUserProviderEnsureRepoOrgForbidden(t *testing.T) {
	p := testUserProvider(t, userMux(t, nil, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	_, err := p.EnsureRepo(context.Background(), "acme/state")
	var forb *ErrRepoCreateForbidden
	if !errors.As(err, &forb) {
		t.Fatalf("err = %v, want ErrRepoCreateForbidden", err)
	}
	if strings.Contains(err.Error(), "tenant zone flow") {
		t.Fatalf("user-mode error must not reference the platform zone flow: %v", err)
	}
}

func TestUserProviderEnsureRepoCreateRace(t *testing.T) {
	p := testUserProvider(t, userMux(t, nil, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_ = json.NewEncoder(w).Encode(map[string]any{"message": "name already exists on this account"})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	url, err := p.EnsureRepo(context.Background(), "octocat/state")
	if err != nil {
		t.Fatalf("422 race must be treated as existing: %v", err)
	}
	if !strings.HasSuffix(url, "/octocat/state.git") {
		t.Fatalf("url = %q", url)
	}
}

func TestUserProviderNeverMintsInstallationToken(t *testing.T) {
	var tokenCalls atomic.Int32
	p := testUserProvider(t, userMux(t, &tokenCalls, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	_, _ = p.ReadFile(context.Background(), "octocat/state", "main", "x")
	if tokenCalls.Load() != 0 {
		t.Fatalf("installation token minted %d times in user mode", tokenCalls.Load())
	}
}

func TestUserCommitAttribution(t *testing.T) {
	var commitBody map[string]any
	p := testUserProvider(t, userMux(t, nil, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/git/ref/heads/main"):
			_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]any{"sha": "base"}})
		case strings.HasSuffix(r.URL.Path, "/git/blobs"):
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"sha": "blob"})
		case strings.HasSuffix(r.URL.Path, "/git/trees"):
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"sha": "tree"})
		case strings.HasSuffix(r.URL.Path, "/git/commits"):
			_ = json.NewDecoder(r.Body).Decode(&commitBody)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"sha": "commit"})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{})
		}
	}))
	_, err := p.CommitFiles(context.Background(), "octocat/state", "main",
		[]gitprovider.File{{Path: "a.txt", Content: []byte("x")}}, "feat: x")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"author", "committer"} {
		id, ok := commitBody[key].(map[string]any)
		if !ok {
			t.Fatalf("commit missing %s: %v", key, commitBody)
		}
		if id["name"] != "octocat" || id["email"] != "octocat@users.noreply.github.com" {
			t.Fatalf("%s = %v", key, id)
		}
	}
}

// TestAppCommitHasNoAttribution pins the model A/B regression: App
// installation commits carry no author/committer overrides (bot
// attribution is GitHub's default).
func TestAppCommitHasNoAttribution(t *testing.T) {
	var commitBody map[string]any
	p := testProvider(t, mux(t, nil, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/git/ref/heads/main"):
			_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]any{"sha": "base"}})
		case strings.HasSuffix(r.URL.Path, "/git/blobs"):
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"sha": "blob"})
		case strings.HasSuffix(r.URL.Path, "/git/trees"):
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"sha": "tree"})
		case strings.HasSuffix(r.URL.Path, "/git/commits"):
			_ = json.NewDecoder(r.Body).Decode(&commitBody)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"sha": "commit"})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{})
		}
	}))
	_, err := p.CommitFiles(context.Background(), "acme/state", "main",
		[]gitprovider.File{{Path: "a.txt", Content: []byte("x")}}, "feat: x")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := commitBody["author"]; ok {
		t.Fatalf("app commit must not set author: %v", commitBody)
	}
	if _, ok := commitBody["committer"]; ok {
		t.Fatalf("app commit must not set committer: %v", commitBody)
	}
}
