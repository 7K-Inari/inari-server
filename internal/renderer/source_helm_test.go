package renderer

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func helmDesc() types.SourceDescriptor {
	return types.SourceDescriptor{
		Kind: types.SourceKindHelm,
		Helm: &types.HelmSource{
			RepoURL: "https://charts.jetstack.io",
			Chart:   "cert-manager",
			Version: "v1.16.2",
		},
	}
}

func TestHelmHandlerMultiSourceApplication(t *testing.T) {
	r := New(nil)
	p := testParams()
	p.Values = json.RawMessage(`{"crds":{"enabled":true},"replicaCount":2}`)
	files, err := r.Render(context.Background(), helmDesc(), p)
	if err != nil {
		t.Fatal(err)
	}
	byPath := filesByPath(files)

	values, ok := byPath["addons/cert-manager/values.yaml"]
	if !ok {
		t.Fatalf("missing values.yaml: %v", byPath)
	}
	if !strings.Contains(string(values), "enabled: true") || !strings.Contains(string(values), "replicaCount: 2") {
		t.Errorf("values content:\n%s", values)
	}

	app, ok := byPath["addons/cert-manager/application.yaml"]
	if !ok {
		t.Fatalf("missing application.yaml: %v", byPath)
	}
	doc := parseDoc(t, app)
	spec := doc["spec"].(map[string]any)
	sources := spec["sources"].([]any)
	if len(sources) != 2 {
		t.Fatalf("sources = %v", sources)
	}
	chart := sources[0].(map[string]any)
	if chart["repoURL"] != "https://charts.jetstack.io" || chart["chart"] != "cert-manager" ||
		chart["targetRevision"] != "v1.16.2" {
		t.Errorf("chart source = %v", chart)
	}
	helm := chart["helm"].(map[string]any)
	vf := helm["valueFiles"].([]any)
	if len(vf) != 1 || vf[0] != "$values/addons/cert-manager/values.yaml" {
		t.Errorf("valueFiles = %v", vf)
	}
	if helm["releaseName"] != "cert-manager" {
		t.Errorf("releaseName = %v", helm["releaseName"])
	}
	ref := sources[1].(map[string]any)
	if ref["repoURL"] != p.RepoURL || ref["ref"] != "values" || ref["targetRevision"] != "main" {
		t.Errorf("values ref = %v", ref)
	}
	// Adoption safety: prune off by default.
	sp := spec["syncPolicy"].(map[string]any)
	if sp["automated"].(map[string]any)["prune"] != false {
		t.Errorf("prune = %v", sp["automated"])
	}
}

func TestHelmHandlerApplicationSetWithClusterOverlays(t *testing.T) {
	r := New(nil)
	p := testParams()
	p.DeployMode = types.AddonDeployModeApplicationSet
	p.Clusters = []ClusterTarget{{ID: "c1", Name: "eu"}, {ID: "c2", Name: "us"}}
	p.SyncOptions = []string{"TakeOwnership=true"}
	files, err := r.Render(context.Background(), helmDesc(), p)
	if err != nil {
		t.Fatal(err)
	}
	byPath := filesByPath(files)
	appset, ok := byPath["addons/cert-manager/applicationset.yaml"]
	if !ok {
		t.Fatalf("missing applicationset.yaml: %v", byPath)
	}
	doc := parseDoc(t, appset)
	tpl := doc["spec"].(map[string]any)["template"].(map[string]any)
	chart := tpl["spec"].(map[string]any)["sources"].([]any)[0].(map[string]any)
	helm := chart["helm"].(map[string]any)
	vf := helm["valueFiles"].([]any)
	if len(vf) != 2 ||
		vf[0] != "$values/addons/cert-manager/values.yaml" ||
		vf[1] != "$values/clusters/{{cluster}}/cert-manager/values.yaml" {
		t.Errorf("valueFiles = %v", vf)
	}
	if helm["ignoreMissingValueFiles"] != true {
		t.Errorf("ignoreMissingValueFiles = %v", helm["ignoreMissingValueFiles"])
	}
	sp := tpl["spec"].(map[string]any)["syncPolicy"].(map[string]any)
	if sp["syncOptions"].([]any)[0] != "TakeOwnership=true" {
		t.Errorf("syncOptions = %v", sp)
	}
	if _, ok := byPath["addons/cert-manager/values.yaml"]; !ok {
		t.Error("values.yaml must be emitted in appset mode too")
	}
}

func TestHelmHandlerValidation(t *testing.T) {
	r := New(nil)
	p := testParams()
	for _, tc := range []struct {
		name string
		mut  func(*types.HelmSource)
		want string
	}{
		{"repoURL", func(h *types.HelmSource) { h.RepoURL = "" }, "repoUrl"},
		{"chart", func(h *types.HelmSource) { h.Chart = "" }, "chart"},
		{"version", func(h *types.HelmSource) { h.Version = "" }, "version"},
	} {
		desc := helmDesc()
		tc.mut(desc.Helm)
		if _, err := r.Render(context.Background(), desc, p); err == nil ||
			!strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}
	if _, err := r.Render(context.Background(), helmDesc(), p); err != nil {
		t.Errorf("valid descriptor: %v", err)
	}
	// Invalid values JSON must fail.
	p.Values = json.RawMessage(`{bad`)
	if _, err := r.Render(context.Background(), helmDesc(), p); err == nil {
		t.Error("expected values parse error")
	}
}

func TestHelmHandlerEmptyValuesStillWritesFile(t *testing.T) {
	r := New(nil)
	files, err := r.Render(context.Background(), helmDesc(), testParams())
	if err != nil {
		t.Fatal(err)
	}
	if string(filesByPath(files)["addons/cert-manager/values.yaml"]) != "{}\n" {
		t.Errorf("empty values should render as {}: %q", filesByPath(files)["addons/cert-manager/values.yaml"])
	}
}
