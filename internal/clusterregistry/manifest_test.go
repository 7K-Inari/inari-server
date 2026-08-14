package clusterregistry

import (
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestRenderInstallManifest(t *testing.T) {
	c := &types.Cluster{ID: "cluster:abc-123"}
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
		"image: ghcr.io/7k-inari/inari-agent:v0.1.0",
		`value: "https://inari.example.com"`,
		`value: "cluster:abc-123"`,
		"namespace: inari-system",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("manifest missing %q\n---\n%s", want, s)
		}
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
