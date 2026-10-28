package renderer

import (
	"context"
	"encoding/json"
	"errors"
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

func staticRGD(doc string) ResolveRGDFunc {
	return func(_ context.Context, ref string) ([]byte, error) {
		if ref == "" {
			return nil, errors.New("empty ref")
		}
		return []byte(doc), nil
	}
}

func kroDesc() types.SourceDescriptor {
	return types.SourceDescriptor{
		Kind: types.SourceKindKRO,
		KRO: &types.KROSource{
			RGDRef:   "curated:postgres-aws@v1alpha1",
			Instance: json.RawMessage(`{"engineVersion":"16","storageGB":50}`),
		},
	}
}

func kroParams() RenderParams {
	return RenderParams{
		Name: "my-db", Namespace: "apps", ID: "my-db",
		AppPrefix: PrefixInstance, DeployMode: types.AddonDeployModeApplication,
		Clusters:   []ClusterTarget{{ID: "c1", Name: "c1"}},
		Prune:      true, // instance deploys keep today's prune-on behavior
		RepoURL:    "https://github.com/inari-dev/acme-inari-state",
		BaseBranch: "main", Path: "clusters/c1/postgres-aws/my-db",
	}
}

func filesByPath(files []RenderedFile) map[string][]byte {
	m := make(map[string][]byte, len(files))
	for _, f := range files {
		m[f.Path] = f.Content
	}
	return m
}

func TestKROHandlerRendersInstanceAndApplication(t *testing.T) {
	r := New(staticRGD(testRGD))
	files, err := r.Render(context.Background(), kroDesc(), kroParams())
	if err != nil {
		t.Fatal(err)
	}
	byPath := filesByPath(files)

	inst, ok := byPath["clusters/c1/postgres-aws/my-db/instance.yaml"]
	if !ok {
		t.Fatalf("missing instance.yaml: %v", byPath)
	}
	for _, want := range []string{
		"apiVersion: kro.run/v1alpha1",
		"kind: PostgresAWS",
		"name: my-db",
		"namespace: apps",
		"engineVersion: \"16\"",
		"storageGB: 50",
	} {
		if !strings.Contains(string(inst), want) {
			t.Errorf("instance manifest missing %q:\n%s", want, inst)
		}
	}

	app, ok := byPath["clusters/c1/postgres-aws/my-db/application.yaml"]
	if !ok {
		t.Fatalf("missing application.yaml: %v", byPath)
	}
	doc := parseDoc(t, app)
	spec := doc["spec"].(map[string]any)
	src := spec["source"].(map[string]any)
	if src["repoURL"] != "https://github.com/inari-dev/acme-inari-state" ||
		src["path"] != "clusters/c1/postgres-aws/my-db" || src["targetRevision"] != "main" {
		t.Errorf("source = %v", src)
	}
	if doc["metadata"].(map[string]any)["name"] != "inari-my-db" {
		t.Errorf("app name = %v", doc["metadata"])
	}
}

func TestKROHandlerApplicationSetMode(t *testing.T) {
	r := New(staticRGD(testRGD))
	p := kroParams()
	p.DeployMode = types.AddonDeployModeApplicationSet
	p.Clusters = []ClusterTarget{{ID: "c1", Name: "eu"}, {ID: "c2", Name: "us"}}
	files, err := r.Render(context.Background(), kroDesc(), p)
	if err != nil {
		t.Fatal(err)
	}
	byPath := filesByPath(files)
	appset, ok := byPath[p.Path+"/applicationset.yaml"]
	if !ok {
		t.Fatalf("missing applicationset.yaml: %v", byPath)
	}
	doc := parseDoc(t, appset)
	if doc["kind"] != "ApplicationSet" {
		t.Fatalf("kind = %v", doc["kind"])
	}
	if _, ok := byPath[p.Path+"/instance.yaml"]; !ok {
		t.Error("instance manifest must still be emitted in appset mode")
	}
}

func TestKROHandlerRequiresResolver(t *testing.T) {
	r := New(nil)
	_, err := r.Render(context.Background(), kroDesc(), kroParams())
	if err == nil || !strings.Contains(err.Error(), "no RGD resolver") {
		t.Fatalf("err = %v", err)
	}
}

func TestKROHandlerResolverErrorPropagates(t *testing.T) {
	r := New(func(context.Context, string) ([]byte, error) { return nil, errors.New("catalog down") })
	_, err := r.Render(context.Background(), kroDesc(), kroParams())
	if err == nil || !strings.Contains(err.Error(), "catalog down") {
		t.Fatalf("err = %v", err)
	}
}

func TestRenderKROInstanceValidation(t *testing.T) {
	if _, err := RenderKROInstance([]byte("spec:\n  schema: {}\n"), "n", "ns", nil); err == nil ||
		!strings.Contains(err.Error(), "spec.schema.kind") {
		t.Fatalf("missing kind: err = %v", err)
	}
	if _, err := RenderKROInstance([]byte("{{{{"), "n", "ns", nil); err == nil {
		t.Fatal("expected parse error")
	}
	if _, err := RenderKROInstance([]byte(testRGD), "n", "ns", json.RawMessage(`{bad`)); err == nil {
		t.Fatal("expected spec parse error")
	}
}
