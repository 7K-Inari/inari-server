package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
)

func testProvider(t *testing.T, handler http.Handler) *Provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	keyFile := filepath.Join(t.TempDir(), "app.pem")
	if err := os.WriteFile(keyFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	p, err := New(Config{AppID: 1, InstallationID: 2, PrivateKeyFile: keyFile, APIBase: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// mux serves token minting plus the given API handler.
func mux(t *testing.T, tokenCalls *int32, api http.HandlerFunc) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/installations/2/access_tokens" {
			if tokenCalls != nil {
				atomic.AddInt32(tokenCalls, 1)
			}
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token": "tok", "expires_at": "2099-01-01T00:00:00Z",
			})
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		api(w, r)
	})
}

func TestEnsureRepoNotFound(t *testing.T) {
	p := testProvider(t, mux(t, nil, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	err := p.EnsureRepo(context.Background(), "acme/missing")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v, want not-found", err)
	}
}

func TestEnsureRepoBadName(t *testing.T) {
	p := testProvider(t, mux(t, nil, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	if err := p.EnsureRepo(context.Background(), "no-slash"); err == nil {
		t.Fatal("want error for repo without owner/name")
	}
}

func TestCommitFilesWritesTreeAndAdvancesRef(t *testing.T) {
	var paths []string
	var patchedRef bool
	p := testProvider(t, mux(t, nil, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/repos/acme/state/git/ref/heads/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": "base123"}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/blobs"):
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": "blob1"})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/trees"):
			var req struct {
				Tree []struct {
					Path string `json:"path"`
				} `json:"tree"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			for _, e := range req.Tree {
				paths = append(paths, e.Path)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": "tree1"})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/commits"):
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": "commit1"})
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/git/refs/heads/"):
			patchedRef = true
			_ = json.NewEncoder(w).Encode(map[string]any{})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	res, err := p.CommitFiles(context.Background(), "acme/state", "main",
		[]gitprovider.File{{Path: "a/b.yaml", Content: []byte("x")}}, "msg")
	if err != nil {
		t.Fatal(err)
	}
	if res.CommitSHA != "commit1" {
		t.Errorf("sha = %q", res.CommitSHA)
	}
	if len(paths) != 1 || paths[0] != "a/b.yaml" {
		t.Errorf("tree paths = %v", paths)
	}
	if !patchedRef {
		t.Error("branch ref was not advanced")
	}
}

func TestCommitFilesSeedsEmptyRepo(t *testing.T) {
	var createdRef bool
	p := testProvider(t, mux(t, nil, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/git/ref/heads/"):
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/blobs"):
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": "blob1"})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/trees"):
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": "tree1"})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/commits"):
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": "commit1"})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			createdRef = true
			_ = json.NewEncoder(w).Encode(map[string]any{})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	if _, err := p.CommitFiles(context.Background(), "acme/state", "main",
		[]gitprovider.File{{Path: "x.yaml", Content: []byte("x")}}, "init"); err != nil {
		t.Fatal(err)
	}
	if !createdRef {
		t.Error("expected POST /git/refs for empty repo")
	}
}

func TestInstallationTokenCached(t *testing.T) {
	var tokenCalls int32
	p := testProvider(t, mux(t, &tokenCalls, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	ctx := context.Background()
	_ = p.EnsureRepo(ctx, "acme/state")
	_ = p.EnsureRepo(ctx, "acme/state")
	if n := atomic.LoadInt32(&tokenCalls); n != 1 {
		t.Errorf("token minted %d times, want 1 (cached)", n)
	}
}

func TestOpenPR(t *testing.T) {
	var prCreated bool
	p := testProvider(t, mux(t, nil, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/git/ref/heads/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": "base123"}})
		case strings.HasSuffix(r.URL.Path, "/git/blobs"):
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": "blob1"})
		case strings.HasSuffix(r.URL.Path, "/git/trees"):
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": "tree1"})
		case strings.HasSuffix(r.URL.Path, "/git/commits"):
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": "commit1"})
		case strings.HasSuffix(r.URL.Path, "/pulls"):
			prCreated = true
			_ = json.NewEncoder(w).Encode(map[string]string{"html_url": "https://github.com/acme/state/pull/1"})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{})
		}
	}))
	res, err := p.OpenPR(context.Background(), "acme/state", "main", "deploy x", "", []gitprovider.File{{Path: "x", Content: []byte("y")}})
	if err != nil {
		t.Fatal(err)
	}
	if !prCreated || res.PRURL != "https://github.com/acme/state/pull/1" {
		t.Errorf("prCreated=%v url=%q", prCreated, res.PRURL)
	}
}
