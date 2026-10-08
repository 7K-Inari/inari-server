package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
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
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound) // new path: empty document
			return
		}
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

func TestVaultWriterPutMergesSiblings(t *testing.T) {
	// Regression: cluster registration writes client-secret AND
	// tunnel-client-secret to the same kv-v2 path. A replacing write
	// erases the sibling key, the agent's ExternalSecret never syncs, and
	// the agent never becomes ready (golden-path deadlock, Oct 2026).
	store := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if len(store) == 0 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"data": store},
			})
		case http.MethodPost:
			var body map[string]map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode: %v", err)
			}
			store = body["data"]
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	w := NewVaultWriter(srv.URL, "tok-1", "secret")
	ctx := context.Background()
	if err := w.Put(ctx, "inari/clusters/abc/oidc-client-secret", "client-secret", "agent-secret"); err != nil {
		t.Fatal(err)
	}
	if err := w.Put(ctx, "inari/clusters/abc/oidc-client-secret", "tunnel-client-secret", "tunnel-secret"); err != nil {
		t.Fatal(err)
	}
	if store["client-secret"] != "agent-secret" {
		t.Fatalf("sibling key lost on second put: store = %+v", store)
	}
	if store["tunnel-client-secret"] != "tunnel-secret" {
		t.Fatalf("second key missing: store = %+v", store)
	}
	// Overwriting one key must keep the other and update the value.
	if err := w.Put(ctx, "inari/clusters/abc/oidc-client-secret", "client-secret", "rotated"); err != nil {
		t.Fatal(err)
	}
	if store["client-secret"] != "rotated" || store["tunnel-client-secret"] != "tunnel-secret" {
		t.Fatalf("overwrite lost data: store = %+v", store)
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

func writeJWT(t *testing.T, jwt string) string {
	t.Helper()
	p := t.TempDir() + "/token"
	if err := os.WriteFile(p, []byte(jwt+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVaultWriterKubernetesLoginAndPut(t *testing.T) {
	jwtPath := writeJWT(t, "sa-jwt-1")
	var logins int
	var gotRole, gotJWT, gotPutToken, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/kubernetes/login":
			logins++
			var in struct {
				Role string `json:"role"`
				JWT  string `json:"jwt"`
			}
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				t.Errorf("decode login: %v", err)
			}
			gotRole, gotJWT = in.Role, in.JWT
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{"client_token": "vault-tok-1", "lease_duration": 3600},
			})
		case "/v1/secret/data/inari/clusters/abc/oidc-client-secret":
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusNotFound) // new path: empty document
				return
			}
			gotPutToken = r.Header.Get("X-Vault-Token")
			gotPath = r.URL.Path
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	w := NewVaultWriterKubernetes(srv.URL, "", "inari-server", "", jwtPath)
	if err := w.Put(context.Background(), "inari/clusters/abc/oidc-client-secret", "client-secret", "s3cr3t"); err != nil {
		t.Fatal(err)
	}
	if logins != 1 {
		t.Errorf("logins = %d, want 1", logins)
	}
	if gotRole != "inari-server" || gotJWT != "sa-jwt-1" {
		t.Errorf("login body role=%q jwt=%q", gotRole, gotJWT)
	}
	if gotPutToken != "vault-tok-1" {
		t.Errorf("put token header = %q", gotPutToken)
	}
	if gotPath != "/v1/secret/data/inari/clusters/abc/oidc-client-secret" {
		t.Errorf("put path = %q", gotPath)
	}

	// Second Put within the lease must reuse the cached token (no re-login).
	if err := w.Put(context.Background(), "inari/clusters/abc/oidc-client-secret", "client-secret", "s3cr3t"); err != nil {
		t.Fatal(err)
	}
	if logins != 1 {
		t.Errorf("logins after second put = %d, want 1 (cached token)", logins)
	}
}

func TestVaultWriterKubernetesReloginOn401(t *testing.T) {
	jwtPath := writeJWT(t, "sa-jwt-1")
	var logins, puts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/kubernetes/login" {
			logins++
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{"client_token": fmt.Sprintf("vault-tok-%d", logins), "lease_duration": 3600},
			})
			return
		}
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound) // new path: empty document
			return
		}
		puts++
		if puts == 1 {
			// First token already revoked: force a re-login + retry.
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"errors":["invalid token"]}`))
			return
		}
		if got := r.Header.Get("X-Vault-Token"); got != "vault-tok-2" {
			t.Errorf("retry token = %q, want vault-tok-2", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	w := NewVaultWriterKubernetes(srv.URL, "", "inari-server", "", jwtPath)
	if err := w.Put(context.Background(), "inari/clusters/abc/oidc-client-secret", "client-secret", "x"); err != nil {
		t.Fatal(err)
	}
	if logins != 2 || puts != 2 {
		t.Errorf("logins=%d puts=%d, want 2 and 2", logins, puts)
	}
}

func TestVaultWriterKubernetesLoginError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
	}))
	defer srv.Close()
	w := NewVaultWriterKubernetes(srv.URL, "", "inari-server", "", writeJWT(t, "sa-jwt-1"))
	if err := w.Put(context.Background(), "inari/clusters/abc/oidc-client-secret", "client-secret", "x"); err == nil {
		t.Fatal("expected error when kubernetes login fails")
	}
}
