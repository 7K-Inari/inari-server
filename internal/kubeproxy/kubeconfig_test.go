package kubeproxy

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRenderKubeconfigGateway(t *testing.T) {
	out, err := RenderKubeconfig(KubeconfigOptions{
		Name:      "acme-c1",
		ServerURL: "https://proxy.example.com/api/v1/tenants/acme/clusters/c1/proxy",
		IssuerURL: "https://keycloak.example.com/realms/inari",
		ClientID:  "org-acme-kubectl",
	})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("rendered kubeconfig is not YAML: %v", err)
	}
	for _, want := range []string{
		"current-context: acme-c1",
		"server: https://proxy.example.com/api/v1/tenants/acme/clusters/c1/proxy",
		"command: kubelogin",
		"--oidc-issuer-url",
		"https://keycloak.example.com/realms/inari",
		"--oidc-client-id",
		"org-acme-kubectl",
		"--oidc-extra-scope",
		"organization",
		"--grant-type",
		"device-code",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered kubeconfig missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "token:") || strings.Contains(out, "client-secret") {
		t.Error("kubeconfig must be secret-free")
	}
}

func TestRenderKubeconfigAuthCode(t *testing.T) {
	out, err := RenderKubeconfig(KubeconfigOptions{
		Name: "n", ServerURL: "https://s", IssuerURL: "https://i", ClientID: "c",
		GrantType: GrantTypeAuthCode,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "authcode") {
		t.Error("grant type not honored")
	}
}

func TestRenderKubeconfigInvalid(t *testing.T) {
	if _, err := RenderKubeconfig(KubeconfigOptions{}); err == nil {
		t.Fatal("empty options accepted")
	}
	if _, err := RenderKubeconfig(KubeconfigOptions{
		Name: "n", ServerURL: "s", IssuerURL: "i", ClientID: "c", GrantType: "ropc",
	}); err == nil {
		t.Fatal("unsupported grant type accepted")
	}
}

func TestProxyURL(t *testing.T) {
	got := ProxyURL("https://proxy.example.com/", "acme", "c1")
	want := "https://proxy.example.com/api/v1/tenants/acme/clusters/c1/proxy"
	if got != want {
		t.Fatalf("ProxyURL = %q, want %q", got, want)
	}
}

func TestStaticFlagEvaluator(t *testing.T) {
	if !(StaticFlagEvaluator{Enabled: true}).KubectlAccessEnabled(nil) {
		t.Fatal("enabled evaluator reports disabled")
	}
	if (StaticFlagEvaluator{}).KubectlAccessEnabled(nil) {
		t.Fatal("zero-value evaluator should default to disabled unless configured on")
	}
}
