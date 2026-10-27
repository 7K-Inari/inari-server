package orchestrator

import (
	"encoding/json"
	"testing"

	"github.com/7K-Inari/inari-server/internal/renderer"
	"github.com/7K-Inari/inari-server/internal/types"
)

// Parity with the pre-migration render.go output: the renderer must emit
// byte-identical manifests for the kro single-cluster deploy path so the
// live deploy flow is unchanged by the migration.

func TestInstanceManifestParity(t *testing.T) {
	payload, _ := json.Marshal(map[string]string{"rgd": testRGD})
	ver := &types.CatalogItemVersion{Payload: payload}
	spec := json.RawMessage(`{"engineVersion":"16","storageGB":50}`)

	wrapped, err := RenderInstanceManifest(ver, "my-db", "apps", spec)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := renderer.RenderKROInstance([]byte(testRGD), "my-db", "apps", spec)
	if err != nil {
		t.Fatal(err)
	}
	if string(wrapped) != string(direct) {
		t.Errorf("wrapper output diverges:\n%s\n---\n%s", wrapped, direct)
	}
}

func TestArgoCDApplicationParity(t *testing.T) {
	wrapped := RenderArgoCDApplication(ApplicationParams{
		Name:           "inari-my-db",
		Project:        "default",
		RepoURL:        "https://github.com/inari-dev/acme-inari-state",
		Path:           "clusters/c1/postgres-aws/inst-1",
		TargetRevision: "main",
		DestNamespace:  "apps",
	})
	direct := renderer.RenderSingleClusterApplication(renderer.RenderParams{
		Name: "inari-my-db", ID: "inari-my-db", Project: "default",
		RepoURL: "https://github.com/inari-dev/acme-inari-state",
		Path:    "clusters/c1/postgres-aws/inst-1", BaseBranch: "main",
		Namespace: "apps", Prune: true,
	})
	if string(wrapped) != string(direct) {
		t.Errorf("application output diverges:\n%s\n---\n%s", wrapped, direct)
	}
}
