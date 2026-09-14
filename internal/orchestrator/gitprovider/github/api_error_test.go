package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
)

func TestDoReturnsTypedAPIError(t *testing.T) {
	p := testProvider(t, mux(t, nil, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(strings.Repeat("x", 1000)))
	}))
	_, err := p.EnsureRepo(context.Background(), "acme/state")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v (%T), want *APIError", err, err)
	}
	if apiErr.Status != http.StatusForbidden {
		t.Errorf("status = %d", apiErr.Status)
	}
	if len(apiErr.Body) > 512 {
		t.Errorf("body not truncated: %d bytes", len(apiErr.Body))
	}
}

func TestNewWithKeyCommitFiles(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(mux(t, nil, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/git/ref/heads/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": "base123"}})
		case strings.HasSuffix(r.URL.Path, "/git/blobs"):
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": "blob1"})
		case strings.HasSuffix(r.URL.Path, "/git/trees"):
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": "tree1"})
		case strings.HasSuffix(r.URL.Path, "/git/commits"):
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": "commit1"})
		case strings.Contains(r.URL.Path, "/git/refs/heads/"):
			_ = json.NewEncoder(w).Encode(map[string]any{})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	p := NewWithKey(1, 2, key, srv.URL)
	res, err := p.CommitFiles(context.Background(), "acme/state", "main",
		[]gitprovider.File{{Path: "a.yaml", Content: []byte("x")}}, "msg")
	if err != nil {
		t.Fatal(err)
	}
	if res.CommitSHA != "commit1" {
		t.Errorf("sha = %q", res.CommitSHA)
	}
}
