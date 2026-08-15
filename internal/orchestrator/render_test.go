package orchestrator

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

const testRGD = `apiVersion: kro.run/v1alpha1
kind: ResourceGraphDefinition
metadata:
  name: postgres-aws
spec:
  schema:
    apiVersion: v1alpha1
    kind: PostgresAWS
    spec:
      engineVersion: "16"
  resources: []
`

func TestRenderInstanceManifest(t *testing.T) {
	payload, _ := json.Marshal(map[string]string{"rgd": testRGD})
	ver := &types.CatalogItemVersion{Payload: payload}
	spec := json.RawMessage(`{"engineVersion":"16","storageGB":50}`)

	m, err := RenderInstanceManifest(ver, "my-db", "apps", spec)
	if err != nil {
		t.Fatal(err)
	}
	y := string(m)
	for _, want := range []string{
		"apiVersion: kro.run/v1alpha1",
		"kind: PostgresAWS",
		"name: my-db",
		"namespace: apps",
		"engineVersion: \"16\"",
		"storageGB: 50",
	} {
		if !strings.Contains(y, want) {
			t.Errorf("rendered manifest missing %q:\n%s", want, y)
		}
	}
}

func TestRenderArgoCDApplication(t *testing.T) {
	app := RenderArgoCDApplication(ApplicationParams{
		Name:           "inari-my-db",
		Project:        "default",
		RepoURL:        "https://github.com/inari-dev/acme-inari-state",
		Path:           "clusters/c1/postgres-aws/inst-1",
		TargetRevision: "main",
		DestNamespace:  "apps",
	})
	y := string(app)
	for _, want := range []string{
		"kind: Application",
		"name: inari-my-db",
		"repoURL: https://github.com/inari-dev/acme-inari-state",
		"automated:",
		"selfHeal: true",
		"prune: true",
	} {
		if !strings.Contains(y, want) {
			t.Errorf("application manifest missing %q:\n%s", want, y)
		}
	}
}

func TestRepoPathDeterministic(t *testing.T) {
	p := RepoPath("c1", "curated:postgres-aws", "inst-1")
	if p != "clusters/c1/postgres-aws/inst-1" {
		t.Errorf("RepoPath = %q", p)
	}
}
