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
	"os"
	"strings"
	"sync"
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
// authenticates with a Vault identity whose policy permits
// `update` on `<mount>/data/inari/clusters/*` only — the hub never reads
// tenant paths and cannot write outside the cluster prefix. Agent-cluster
// ESO authenticates via the `inari-platform` SecretStore against a Vault
// role with `read` on the same prefix; per-cluster path scoping (one Vault
// role per cluster) is a deliberate follow-up once the platform Vault
// onboarding flow exists.
//
// Two auth methods are supported:
//   - token: a static Vault token (back-compat; simple but expires and must
//     be rotated out-of-band, with a pod restart to pick up the new value).
//   - kubernetes: the pod's ServiceAccount JWT is exchanged at
//     auth/<authPath>/login for a short-lived Vault token bound to `role`.
//     The writer re-logs-in before the lease elapses and once more on a
//     401/403 from Vault (early revocation), so there is no secret material
//     to distribute and no expiry outage.
type VaultWriter struct {
	addr  string
	mount string
	http  *http.Client

	// token auth
	token string

	// kubernetes auth
	k8sAuth     bool
	k8sRole     string
	k8sAuthPath string
	jwtPath     string

	mu       sync.Mutex
	leaseTok string
	leaseExp time.Time
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

// NewVaultWriterKubernetes returns a writer that authenticates via the Vault
// Kubernetes auth method: the ServiceAccount JWT at jwtPath is exchanged at
// auth/<authPath>/login for a token bound to role. authPath defaults to
// "kubernetes"; jwtPath defaults to the in-pod ServiceAccount token path.
func NewVaultWriterKubernetes(addr, mount, role, authPath, jwtPath string) *VaultWriter {
	w := NewVaultWriter(addr, "", mount)
	w.k8sAuth = true
	w.k8sRole = role
	w.k8sAuthPath = authPath
	if w.k8sAuthPath == "" {
		w.k8sAuthPath = "kubernetes"
	}
	w.jwtPath = jwtPath
	if w.jwtPath == "" {
		w.jwtPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	}
	return w
}

func (v *VaultWriter) Put(ctx context.Context, path, key, value string) error {
	token, err := v.currentToken(ctx, false)
	if err != nil {
		return err
	}
	status, body, err := v.put(ctx, path, key, value, token)
	if err != nil {
		return err
	}
	if status == http.StatusOK || status == http.StatusNoContent {
		return nil
	}
	// On auth failure with kubernetes auth, re-login once and retry: the
	// cached token may have been revoked or expired ahead of schedule.
	if v.k8sAuth && (status == http.StatusUnauthorized || status == http.StatusForbidden) {
		token, lerr := v.currentToken(ctx, true)
		if lerr != nil {
			return fmt.Errorf("vault: put %s: status %d and re-login failed: %v", path, status, lerr)
		}
		status, body, err = v.put(ctx, path, key, value, token)
		if err != nil {
			return err
		}
		if status == http.StatusOK || status == http.StatusNoContent {
			return nil
		}
	}
	return fmt.Errorf("vault: put %s: status %d: %s", path, status, body)
}

// currentToken returns a valid Vault token. For token auth it is the static
// token; for kubernetes auth it logs in (or re-logs-in when force is set or
// the cached token is within 20% of its lease end).
func (v *VaultWriter) currentToken(ctx context.Context, force bool) (string, error) {
	if !v.k8sAuth {
		return v.token, nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if !force && v.leaseTok != "" && time.Now().Before(v.leaseExp) {
		return v.leaseTok, nil
	}
	return v.loginLocked(ctx)
}

func (v *VaultWriter) loginLocked(ctx context.Context) (string, error) {
	jwt, err := os.ReadFile(v.jwtPath)
	if err != nil {
		return "", fmt.Errorf("vault: read service account token %s: %w", v.jwtPath, err)
	}
	reqBody, err := json.Marshal(map[string]string{"role": v.k8sRole, "jwt": strings.TrimSpace(string(jwt))})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		v.addr+"/v1/auth/"+v.k8sAuthPath+"/login", bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault: kubernetes login: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("vault: kubernetes login: status %d: %s", resp.StatusCode, b)
	}
	var out struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("vault: kubernetes login: decode: %w", err)
	}
	if out.Auth.ClientToken == "" {
		return "", fmt.Errorf("vault: kubernetes login: empty client_token")
	}
	v.leaseTok = out.Auth.ClientToken
	// Re-login at 80% of the lease; floor at 1 minute lease to avoid
	// pathological churn on misconfigured mounts.
	lease := time.Duration(out.Auth.LeaseDuration) * time.Second
	if lease < time.Minute {
		lease = time.Minute
	}
	v.leaseExp = time.Now().Add(lease * 4 / 5)
	return v.leaseTok, nil
}

func (v *VaultWriter) put(ctx context.Context, path, key, value, token string) (int, string, error) {
	body, err := json.Marshal(map[string]any{"data": map[string]string{key: value}})
	if err != nil {
		return 0, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		v.addr+"/v1/"+v.mount+"/data/"+path, bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.http.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("vault: put %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}
