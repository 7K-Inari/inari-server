package clusterregistry

import (
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestRenderInstallManifest(t *testing.T) {
	c := &types.Cluster{
		ID:     "cluster:abc-123",
		OrgID:  "org:kc-org-1",
		Labels: map[string]string{"env": "prod", "region": "eu"},
	}
	p := ManifestParams{
		AgentImageRepo: "ghcr.io/7k-inari/inari-agent",
		AgentImageTag:  "v0.1.0",
		GatewayAddress: "https://inari.example.com",
	}
	out, err := RenderInstallManifest(c, "tok-xyz", p)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{
		"registration-token: tok-xyz",
		`image: "ghcr.io/7k-inari/inari-agent:v0.1.0"`,
		"name: INARI_CONTROL_PLANE",
		`value: "https://inari.example.com"`,
		"name: INARI_TENANT_ID",
		`value: "org:kc-org-1"`,
		"name: INARI_CLUSTER_LABELS",
		`value: "env=prod,region=eu"`,
		"name: INARI_REGISTRATION_TOKEN",
		"namespace: inari-system",
		"kind: ServiceAccount",
		"name: inari-agent\n",
		"kind: ClusterRole",
		"name: inari-agent-discovery",
		"kind: ClusterRoleBinding",
		"kind: Role",
		"name: inari-agent-managed",
		"kind: RoleBinding",
		"customresourcedefinitions",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("manifest missing %q\n---\n%s", want, s)
		}
	}
	for _, gone := range []string{"INARI_GATEWAY_ADDRESS", "INARI_CLUSTER_ID"} {
		if strings.Contains(s, gone) {
			t.Errorf("manifest must not contain %q\n---\n%s", gone, s)
		}
	}
}

func TestRenderInstallManifestOmitsEmptyLabels(t *testing.T) {
	c := &types.Cluster{ID: "cluster:abc", OrgID: "org:x"}
	p := ManifestParams{
		AgentImageRepo: "r", AgentImageTag: "v1", GatewayAddress: "https://g",
	}
	out, err := RenderInstallManifest(c, "t", p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "INARI_CLUSTER_LABELS") {
		t.Errorf("labels env must be omitted when cluster has no labels:\n%s", out)
	}
}

func TestRenderInstallManifestRequiresParams(t *testing.T) {
	c := &types.Cluster{ID: "cluster:abc"}
	if _, err := RenderInstallManifest(c, "t", ManifestParams{}); err == nil {
		t.Error("expected error for missing image")
	}
	if _, err := RenderInstallManifest(c, "t", ManifestParams{
		AgentImageRepo: "r", AgentImageTag: "v1",
	}); err == nil {
		t.Error("expected error for missing gateway address")
	}
}
