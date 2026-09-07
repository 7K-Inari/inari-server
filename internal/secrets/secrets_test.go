package secrets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClusterOIDCPath(t *testing.T) {
	got := ClusterOIDCPath("cluster:abc-123")
	if got != "inari/clusters/abc-123/oidc-client-secret" {
		t.Errorf("path = %q", got)
	}
	if got := ClusterOIDCPath("abc-123"); got != "inari/clusters/abc-123/oidc-client-secret" {
		t.Errorf("unprefixed path = %q", got)
	}
}

func TestVaultWriterPut(t *testing.T) {
	var gotAuth, gotPath string
	var gotBody map[string]map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("X-Vault-Token")
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	w := NewVaultWriter(srv.URL, "tok-1", "kv")
	err := w.Put(context.Background(), "inari/clusters/abc/oidc-client-secret", "client-secret", "s3cr3t")
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "tok-1" {
		t.Errorf("token header = %q", gotAuth)
	}
	if gotPath != "/v1/kv/data/inari/clusters/abc/oidc-client-secret" {
		t.Errorf("path = %q", gotPath)
	}
	if gotBody["data"]["client-secret"] != "s3cr3t" {
		t.Errorf("body = %+v", gotBody)
	}
}

func TestVaultWriterPutError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
	}))
	defer srv.Close()
	w := NewVaultWriter(srv.URL, "tok-1", "")
	if err := w.Put(context.Background(), "inari/clusters/abc/oidc-client-secret", "client-secret", "x"); err == nil {
		t.Fatal("expected error on 403")
	}
}
