//go:build e2e

// kubectl-proxy e2e-access contract: against a live control plane, assert
// the per-cluster disable setting round-trips via
// PATCH /api/v1/tenants/{org}/clusters/{id}, that cluster payloads carry
// the server-computed kubectlProxyEnabled, and that GET /api/v1/features
// reflects the global INARI_DISABLE_KUBECTL_PROXY kill switch.
//
// Precedence matrix (effective = !global && !cluster):
//   - default server: enabled until the per-cluster setting is flipped
//   - E2E_KUBECTL_PROXY_DISABLED=1: server runs with the kill switch set;
//     the test then asserts every cluster reports enabled=false regardless
//     of the per-cluster setting.
//
// Config via env (same harness as api_schema_e2e_test.go):
//
//	E2E_BASE_URL                 server base URL (required; test skips if unset)
//	E2E_KEYCLOAK_URL             Keycloak base URL (required)
//	E2E_ORG                      tenant slug (default: first entry of /api/v1/tenants)
//	E2E_KUBECTL_PROXY_DISABLED   "1" when the server under test runs with
//	                             INARI_DISABLE_KUBECTL_PROXY=true
package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

func doJSON(t *testing.T, method, base, token, path string, reqBody any) (int, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if reqBody != nil {
		raw, err := json.Marshal(reqBody)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, base+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("%s %s: decode: %v: %s", method, path, err, raw)
		}
	}
	return resp.StatusCode, out
}

func TestKubectlProxyAccessFlow(t *testing.T) {
	base := os.Getenv("E2E_BASE_URL")
	if base == "" {
		t.Skip("E2E_BASE_URL unset")
	}
	token := userToken(t)
	org := os.Getenv("E2E_ORG")
	if org == "" {
		tenants := getJSON(t, base, token, "/api/v1/tenants")
		list, _ := tenants.(map[string]any)["tenants"].([]any)
		if len(list) == 0 {
			t.Skip("no tenants visible to the e2e user")
		}
		org, _ = list[0].(map[string]any)["slug"].(string)
	}
	globalDisabled := os.Getenv("E2E_KUBECTL_PROXY_DISABLED") == "1"

	// The features endpoint mirrors the global kill switch.
	code, features := doJSON(t, http.MethodGet, base, token, "/api/v1/features", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /api/v1/features: status %d", code)
	}
	kp, _ := features["kubectlProxy"].(map[string]any)
	enabled, _ := kp["enabled"].(bool)
	if enabled != !globalDisabled {
		t.Errorf("features.kubectlProxy.enabled = %v, want %v (E2E_KUBECTL_PROXY_DISABLED=%v)",
			enabled, !globalDisabled, globalDisabled)
	}

	// Register a throwaway cluster for the settings round-trip.
	code, created := doJSON(t, http.MethodPost, base, token, "/api/v1/tenants/"+org+"/clusters",
		map[string]any{"name": "e2e-kubectl-proxy"})
	if code != http.StatusOK {
		t.Fatalf("create cluster: status %d: %v", code, created)
	}
	cluster, _ := created["cluster"].(map[string]any)
	clusterID, _ := cluster["id"].(string)
	if clusterID == "" {
		t.Fatalf("create cluster: no id in %v", created)
	}
	defer func() {
		_, _ = doJSON(t, http.MethodDelete, base, token, "/api/v1/tenants/"+org+"/clusters/"+clusterID, nil)
	}()

	// Defaults: setting off; effective enablement is the global inverse.
	if disabled, _ := cluster["kubectlProxyDisabled"].(bool); disabled {
		t.Error("cluster.kubectlProxyDisabled = true, want false by default")
	}
	if eff, _ := created["kubectlProxyEnabled"].(bool); eff != !globalDisabled {
		t.Errorf("kubectlProxyEnabled = %v, want %v", eff, !globalDisabled)
	}

	// Disable per-cluster: effective must go false regardless of global.
	code, patched := doJSON(t, http.MethodPatch, base, token,
		"/api/v1/tenants/"+org+"/clusters/"+clusterID,
		map[string]any{"kubectlProxyDisabled": true})
	if code != http.StatusOK {
		t.Fatalf("PATCH disable: status %d: %v", code, patched)
	}
	patchedCluster, _ := patched["cluster"].(map[string]any)
	if disabled, _ := patchedCluster["kubectlProxyDisabled"].(bool); !disabled {
		t.Error("after PATCH: kubectlProxyDisabled = false, want true")
	}
	if eff, _ := patched["kubectlProxyEnabled"].(bool); eff {
		t.Error("after PATCH: kubectlProxyEnabled = true, want false")
	}

	// Persisted on read-back.
	code, got := doJSON(t, http.MethodGet, base, token, "/api/v1/tenants/"+org+"/clusters/"+clusterID, nil)
	if code != http.StatusOK {
		t.Fatalf("GET cluster: status %d", code)
	}
	gotCluster, _ := got["cluster"].(map[string]any)
	if disabled, _ := gotCluster["kubectlProxyDisabled"].(bool); !disabled {
		t.Error("GET: kubectlProxyDisabled = false, want true (persisted)")
	}

	// Re-enable: effective follows the global flag again.
	code, reEnabled := doJSON(t, http.MethodPatch, base, token,
		"/api/v1/tenants/"+org+"/clusters/"+clusterID,
		map[string]any{"kubectlProxyDisabled": false})
	if code != http.StatusOK {
		t.Fatalf("PATCH re-enable: status %d: %v", code, reEnabled)
	}
	if eff, _ := reEnabled["kubectlProxyEnabled"].(bool); eff != !globalDisabled {
		t.Errorf("after re-enable: kubectlProxyEnabled = %v, want %v", eff, !globalDisabled)
	}
}
