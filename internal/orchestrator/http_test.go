package orchestrator

import (
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func byo(appID, instID int64, apiBase string) *types.GitHubAppConfig {
	return &types.GitHubAppConfig{
		AppID: appID, InstallationID: instID, APIBase: apiBase,
		KeyRef: &types.GitHubAppSecretRef{Namespace: "tenant-acme", SecretName: "gh-app", Key: "private-key.pem"},
	}
}

func TestValidateGitHubApp(t *testing.T) {
	h := NewHandler(nil, nil, nil)
	cases := []struct {
		name    string
		app     *types.GitHubAppConfig
		wantErr string
	}{
		{"nil ok", nil, ""},
		{"valid", byo(1, 2, ""), ""},
		{"valid ghe", byo(1, 2, "https://ghe.example.com/api/v3"), ""},
		{"app id zero", byo(0, 2, ""), "positive"},
		{"installation negative", byo(1, -2, ""), "positive"},
		{"http base", byo(1, 2, "http://ghe.example.com/api/v3"), "https"},
		{"bad path", byo(1, 2, "https://ghe.example.com/evil"), "/api/v3"},
		{"query", byo(1, 2, "https://ghe.example.com/api/v3?x=1"), "query"},
		{"fragment", byo(1, 2, "https://ghe.example.com/api/v3#x"), "query"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := h.validateGitHubApp(tc.app)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want substring %q", err, tc.wantErr)
				}
			}
		})
	}
}

func TestValidateGitHubAppMissingKeyRef(t *testing.T) {
	h := NewHandler(nil, nil, nil)
	app := byo(1, 2, "")
	app.KeyRef = nil
	if err := h.validateGitHubApp(app); err == nil {
		t.Fatal("want error for missing keyRef")
	}
}

func TestValidateGitHubAppAllowlist(t *testing.T) {
	h := NewHandler(nil, nil, nil).WithAllowedAPIBases([]string{"ghe.corp.example"})
	if err := h.validateGitHubApp(byo(1, 2, "https://ghe.corp.example/api/v3")); err != nil {
		t.Fatalf("allowlisted host rejected: %v", err)
	}
	if err := h.validateGitHubApp(byo(1, 2, "https://ghe.evil.example/api/v3")); err == nil {
		t.Fatal("non-allowlisted host accepted")
	}
}

func TestValidateGitHubAppAllowlistForms(t *testing.T) {
	// host:port entries must match an apiBase on that port (Hostname()
	// strips ports, so a naive comparison can never match).
	h := NewHandler(nil, nil, nil).WithAllowedAPIBases([]string{"ghe.corp.example:8443"})
	if err := h.validateGitHubApp(byo(1, 2, "https://ghe.corp.example:8443/api/v3")); err != nil {
		t.Fatalf("host:port allowlist entry rejected: %v", err)
	}
	if err := h.validateGitHubApp(byo(1, 2, "https://ghe.corp.example/api/v3")); err == nil {
		t.Fatal("wrong port accepted against host:port allowlist entry")
	}
	// URL-form entries normalize to their host (path ignored).
	h = NewHandler(nil, nil, nil).WithAllowedAPIBases([]string{"https://ghe.corp.example/api/v3"})
	if err := h.validateGitHubApp(byo(1, 2, "https://ghe.corp.example/api/v3")); err != nil {
		t.Fatalf("URL-form allowlist entry rejected: %v", err)
	}
}
