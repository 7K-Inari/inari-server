// Package secrets is the control plane's secret-store seam (plan §5.2,
// "small kernel" module): it writes platform-owned secrets — today only the
// per-cluster OIDC client secret promised by the registration exchange — to
// the platform Vault so the agent cluster's ESO SecretStore can project them
// in-cluster. Secret values never transit the agent-facing API.
package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ClusterOIDCPath is the Vault KV path for a cluster's OIDC client secret.
// The "cluster:" type prefix is trimmed — Vault paths should not carry the
// control plane's typed-ID separator.
func ClusterOIDCPath(clusterID string) string {
	return "inari/clusters/" + strings.TrimPrefix(clusterID, "cluster:") + "/oidc-client-secret"
}

// Writer persists platform-owned secrets. Implemented by VaultWriter; nil in
// the gateway config means delivery is unconfigured and registration must
// fail explicitly (never silently promise a delivery that cannot happen).
type Writer interface {
	// Put writes value at path (relative to the KV mount), overwriting any
	// prior version. Must be idempotent — registration retries re-write.
	Put(ctx context.Context, path, key, value string) error
}

// VaultWriter writes to a Vault KV v2 mount over HTTP.
//
// Policy scoping (documented choice, plan §5.10): the control plane
// authenticates with a Vault token whose policy permits
// `update` on `<mount>/data/inari/clusters/*` only — the hub never reads
// tenant paths and cannot write outside the cluster prefix. Agent-cluster
// ESO authenticates via the `inari-platform` SecretStore against a Vault
// role with `read` on the same prefix; per-cluster path scoping (one Vault
// role per cluster) is a deliberate follow-up once the platform Vault
// onboarding flow exists.
type VaultWriter struct {
	addr  string
	token string
	mount string
	http  *http.Client
}

func NewVaultWriter(addr, token, mount string) *VaultWriter {
	if mount == "" {
		mount = "secret"
	}
	return &VaultWriter{
		addr:  strings.TrimRight(addr, "/"),
		token: token,
		mount: mount,
		http:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (v *VaultWriter) Put(ctx context.Context, path, key, value string) error {
	body, err := json.Marshal(map[string]any{"data": map[string]string{key: value}})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		v.addr+"/v1/"+v.mount+"/data/"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", v.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.http.Do(req)
	if err != nil {
		return fmt.Errorf("vault: put %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vault: put %s: status %d: %s", path, resp.StatusCode, b)
	}
	return nil
}
