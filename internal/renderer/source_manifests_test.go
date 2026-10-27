package renderer

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func manifestsDesc(inline string, params map[string]string) types.SourceDescriptor {
	return types.SourceDescriptor{
		Kind:      types.SourceKindManifests,
		Manifests: &types.ManifestSource{Inline: json.RawMessage(inline), Params: params},
	}
}

func manifestsParams() RenderParams {
	return RenderParams{
		Name: "netpol", Namespace: "apps", ID: "netpol-1",
		AppPrefix: PrefixInstance, DeployMode: types.AddonDeployModeApplication,
		Clusters: []ClusterTarget{{ID: "c1", Name: "c1"}},
		RepoURL:  "https://github.com/acme/state", BaseBranch: "main",
		Path: "clusters/c1/policies/netpol-1",
	}
}

func TestManifestsHandlerInlineMultiDoc(t *testing.T) {
	r := New(nil)
	inline := `apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  key: value
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
`
	files, err := r.Render(context.Background(), manifestsDesc(mustJSONString(inline), nil), manifestsParams())
	if err != nil {
		t.Fatal(err)
	}
	byPath := filesByPath(files)
	cm, ok := byPath["clusters/c1/policies/netpol-1/manifests/00-configmap-app-config.yaml"]
	if !ok {
		t.Fatalf("missing configmap manifest: %v", byPath)
	}
	if !strings.Contains(string(cm), "kind: ConfigMap") {
		t.Errorf("cm content:\n%s", cm)
	}
	if _, ok := byPath["clusters/c1/policies/netpol-1/manifests/01-deployment-web.yaml"]; !ok {
		t.Errorf("missing deployment manifest: %v", byPath)
	}
	app := parseDoc(t, byPath["clusters/c1/policies/netpol-1/application.yaml"])
	src := app["spec"].(map[string]any)["source"].(map[string]any)
	if src["path"] != "clusters/c1/policies/netpol-1/manifests" {
		t.Errorf("application should source the manifests dir: %v", src)
	}
}

func TestManifestsHandlerJSONArrayInput(t *testing.T) {
	r := New(nil)
	docs := []string{
		"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: one\n",
		"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: two\n",
	}
	raw, _ := json.Marshal(docs)
	files, err := r.Render(context.Background(), manifestsDesc(string(raw), nil), manifestsParams())
	if err != nil {
		t.Fatal(err)
	}
	byPath := filesByPath(files)
	if _, ok := byPath["clusters/c1/policies/netpol-1/manifests/00-configmap-one.yaml"]; !ok {
		t.Errorf("missing doc 0: %v", byPath)
	}
	if _, ok := byPath["clusters/c1/policies/netpol-1/manifests/01-configmap-two.yaml"]; !ok {
		t.Errorf("missing doc 1: %v", byPath)
	}
}

func TestManifestsHandlerParamSubstitution(t *testing.T) {
	r := New(nil)
	inline := "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: ${policyName}\n  namespace: ${ns}\n"
	files, err := r.Render(context.Background(),
		manifestsDesc(mustJSONString(inline), map[string]string{"policyName": "deny-all", "ns": "apps"}),
		manifestsParams())
	if err != nil {
		t.Fatal(err)
	}
	content := string(filesByPath(files)["clusters/c1/policies/netpol-1/manifests/00-networkpolicy-deny-all.yaml"])
	if strings.Contains(content, "${") || !strings.Contains(content, "name: deny-all") ||
		!strings.Contains(content, "namespace: apps") {
		t.Errorf("substituted content:\n%s", content)
	}
}

func TestManifestsHandlerValidation(t *testing.T) {
	r := New(nil)
	p := manifestsParams()

	// Doc without metadata.name is rejected.
	bad := mustJSONString("apiVersion: v1\nkind: ConfigMap\n")
	if _, err := r.Render(context.Background(), manifestsDesc(bad, nil), p); err == nil ||
		!strings.Contains(err.Error(), "metadata.name") {
		t.Errorf("nameless doc: err = %v", err)
	}
	// Doc without kind is rejected.
	bad = mustJSONString("metadata:\n  name: x\n")
	if _, err := r.Render(context.Background(), manifestsDesc(bad, nil), p); err == nil {
		t.Error("kindless doc: expected error")
	}
	// Empty inline is rejected.
	if _, err := r.Render(context.Background(), manifestsDesc(`""`, nil), p); err == nil {
		t.Error("empty inline: expected error")
	}
	// Unparseable YAML is rejected.
	if _, err := r.Render(context.Background(), manifestsDesc(mustJSONString(":\n  - ["), nil), p); err == nil {
		t.Error("bad YAML: expected error")
	}
}

func TestManifestsHandlerApplicationSet(t *testing.T) {
	r := New(nil)
	p := manifestsParams()
	p.DeployMode = types.AddonDeployModeApplicationSet
	p.AppPrefix = PrefixAddon
	p.Clusters = []ClusterTarget{{ID: "c1", Name: "eu"}}
	inline := mustJSONString("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n")
	files, err := r.Render(context.Background(), manifestsDesc(inline, nil), p)
	if err != nil {
		t.Fatal(err)
	}
	doc := parseDoc(t, filesByPath(files)[p.Path+"/applicationset.yaml"])
	tpl := doc["spec"].(map[string]any)["template"].(map[string]any)
	if tpl["spec"].(map[string]any)["source"].(map[string]any)["path"] != p.Path+"/manifests" {
		t.Errorf("appset template source = %v", tpl["spec"])
	}
}

func mustJSONString(s string) string {
	raw, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(raw)
}
