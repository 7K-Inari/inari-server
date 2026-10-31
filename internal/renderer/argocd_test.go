package renderer

import (
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
	"gopkg.in/yaml.v3"
)

func parseDoc(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("rendered YAML does not parse: %v\n%s", err, b)
	}
	return doc
}

func TestBuildApplicationGitSource(t *testing.T) {
	p := testParams()
	app := buildApplication(p, map[string]any{"source": gitSource(p, p.Path)})
	doc := parseDoc(t, app)

	if doc["kind"] != "Application" {
		t.Fatalf("kind = %v", doc["kind"])
	}
	meta := doc["metadata"].(map[string]any)
	if meta["name"] != "inari-addon-abc123" || meta["namespace"] != "argocd" {
		t.Errorf("metadata = %v", meta)
	}
	spec := doc["spec"].(map[string]any)
	if spec["project"] != "default" {
		t.Errorf("project = %v", spec["project"])
	}
	src := spec["source"].(map[string]any)
	if src["repoURL"] != p.RepoURL || src["path"] != p.Path || src["targetRevision"] != "main" {
		t.Errorf("source = %v", src)
	}
	dest := spec["destination"].(map[string]any)
	if dest["server"] != localServer || dest["namespace"] != "cert-manager" {
		t.Errorf("destination = %v", dest)
	}
	sp := spec["syncPolicy"].(map[string]any)
	auto := sp["automated"].(map[string]any)
	if auto["selfHeal"] != true {
		t.Errorf("selfHeal = %v", auto["selfHeal"])
	}
	if auto["prune"] != false {
		t.Errorf("prune must default to false (decision 2), got %v", auto["prune"])
	}
	if _, ok := sp["syncOptions"]; ok {
		t.Errorf("syncOptions must be omitted when empty: %v", sp)
	}
}

func TestBuildApplicationPruneAndSyncOptions(t *testing.T) {
	p := testParams()
	p.Prune = true
	p.SyncOptions = []string{"TakeOwnership=true"}
	app := buildApplication(p, map[string]any{"source": gitSource(p, p.Path)})
	sp := parseDoc(t, app)["spec"].(map[string]any)["syncPolicy"].(map[string]any)
	if sp["automated"].(map[string]any)["prune"] != true {
		t.Errorf("prune = %v", sp["automated"])
	}
	opts := sp["syncOptions"].([]any)
	if len(opts) != 1 || opts[0] != "TakeOwnership=true" {
		t.Errorf("syncOptions = %v", opts)
	}
}

func TestBuildApplicationMultiSource(t *testing.T) {
	p := testParams()
	sources := []any{
		map[string]any{"repoURL": "https://charts.jetstack.io", "chart": "cert-manager", "targetRevision": "v1.16.2"},
		map[string]any{"repoURL": p.RepoURL, "targetRevision": "main", "ref": "values"},
	}
	app := buildApplication(p, map[string]any{"sources": sources})
	spec := parseDoc(t, app)["spec"].(map[string]any)
	if _, ok := spec["source"]; ok {
		t.Error("multi-source app must not carry spec.source")
	}
	if got := len(spec["sources"].([]any)); got != 2 {
		t.Errorf("sources = %d", got)
	}
}

func TestBuildApplicationSetListGenerator(t *testing.T) {
	p := testParams()
	p.DeployMode = types.AddonDeployModeApplicationSet
	p.Clusters = []ClusterTarget{
		{ID: "c1", Name: "prod-eu"},
		{ID: "c2", Name: "prod-us", Server: "https://prod-us.example"},
	}
	tmplSrc := map[string]any{
		"source": gitSource(p, p.Path),
	}
	appset := buildApplicationSet(p, tmplSrc)
	doc := parseDoc(t, appset)

	if doc["kind"] != "ApplicationSet" {
		t.Fatalf("kind = %v", doc["kind"])
	}
	if doc["metadata"].(map[string]any)["name"] != "inari-addonset-abc123" {
		t.Errorf("name = %v", doc["metadata"])
	}
	spec := doc["spec"].(map[string]any)
	gens := spec["generators"].([]any)
	elements := gens[0].(map[string]any)["list"].(map[string]any)["elements"].([]any)
	if len(elements) != 2 {
		t.Fatalf("elements = %v", elements)
	}
	el0 := elements[0].(map[string]any)
	if el0["cluster"] != "prod-eu" || el0["server"] != localServer {
		t.Errorf("element[0] = %v", el0)
	}
	el1 := elements[1].(map[string]any)
	if el1["cluster"] != "prod-us" || el1["server"] != "https://prod-us.example" {
		t.Errorf("element[1] = %v", el1)
	}

	tpl := spec["template"].(map[string]any)
	if tpl["metadata"].(map[string]any)["name"] != "inari-addon-abc123-{{cluster}}" {
		t.Errorf("template name = %v", tpl["metadata"])
	}
	tspec := tpl["spec"].(map[string]any)
	if tspec["destination"].(map[string]any)["server"] != "{{server}}" {
		t.Errorf("template destination = %v", tspec["destination"])
	}
	if tspec["source"].(map[string]any)["path"] != p.Path {
		t.Errorf("template source = %v", tspec["source"])
	}
}

func TestBuildApplicationSetElementFields(t *testing.T) {
	p := testParams()
	p.DeployMode = types.AddonDeployModeApplicationSet
	p.Clusters = []ClusterTarget{
		{ID: "c1", Name: "prod-eu", Fields: map[string]string{"dexAppName": "dex-c1", "clusterID": "c1"}},
		{ID: "c2", Name: "prod-us", Fields: map[string]string{"dexAppName": "dex-c2", "clusterID": "c2"}},
	}
	appset := buildApplicationSet(p, map[string]any{"source": gitSource(p, p.Path)})
	doc := parseDoc(t, appset)

	spec := doc["spec"].(map[string]any)
	elements := spec["generators"].([]any)[0].(map[string]any)["list"].(map[string]any)["elements"].([]any)
	el0 := elements[0].(map[string]any)
	if el0["cluster"] != "prod-eu" || el0["server"] != localServer {
		t.Errorf("element[0] = %v", el0)
	}
	if el0["dexAppName"] != "dex-c1" || el0["clusterID"] != "c1" {
		t.Errorf("element[0] fields = %v", el0)
	}
	el1 := elements[1].(map[string]any)
	if el1["dexAppName"] != "dex-c2" {
		t.Errorf("element[1] fields = %v", el1)
	}
}

func TestBuildApplicationSetElementFieldsNeverClobberCore(t *testing.T) {
	p := testParams()
	p.DeployMode = types.AddonDeployModeApplicationSet
	p.Clusters = []ClusterTarget{
		{ID: "c1", Name: "prod-eu", Fields: map[string]string{"cluster": "bogus", "server": "bogus"}},
	}
	appset := buildApplicationSet(p, map[string]any{"source": gitSource(p, p.Path)})
	elements := parseDoc(t, appset)["spec"].(map[string]any)["generators"].([]any)[0].(map[string]any)["list"].(map[string]any)["elements"].([]any)
	el := elements[0].(map[string]any)
	if el["cluster"] != "prod-eu" || el["server"] != localServer {
		t.Errorf("fields must not clobber cluster/server: %v", el)
	}
}

func TestBuildApplicationSetAppNameTemplate(t *testing.T) {
	p := testParams()
	p.DeployMode = types.AddonDeployModeApplicationSet
	p.AppNameTemplate = "{{dexAppName}}"
	p.Clusters = []ClusterTarget{{ID: "c1", Name: "prod-eu", Fields: map[string]string{"dexAppName": "dex-c1"}}}
	appset := buildApplicationSet(p, map[string]any{"source": gitSource(p, p.Path)})
	tpl := parseDoc(t, appset)["spec"].(map[string]any)["template"].(map[string]any)
	if got := tpl["metadata"].(map[string]any)["name"]; got != "{{dexAppName}}" {
		t.Errorf("template name = %v, want {{dexAppName}}", got)
	}
}

func TestBuildApplicationSetCascadeDeleteFinalizer(t *testing.T) {
	p := testParams()
	p.DeployMode = types.AddonDeployModeApplicationSet
	p.CascadeDelete = true
	p.Clusters = []ClusterTarget{{ID: "c1", Name: "prod-eu"}}
	appset := buildApplicationSet(p, map[string]any{"source": gitSource(p, p.Path)})
	tpl := parseDoc(t, appset)["spec"].(map[string]any)["template"].(map[string]any)
	fin, ok := tpl["metadata"].(map[string]any)["finalizers"].([]any)
	if !ok || len(fin) != 1 || fin[0] != "resources-finalizer.argocd.argoproj.io" {
		t.Errorf("finalizers = %v, want resources-finalizer", tpl["metadata"])
	}

	// Default: no finalizers (adoption semantics stay unchanged).
	p.CascadeDelete = false
	appset = buildApplicationSet(p, map[string]any{"source": gitSource(p, p.Path)})
	tpl = parseDoc(t, appset)["spec"].(map[string]any)["template"].(map[string]any)
	if _, ok := tpl["metadata"].(map[string]any)["finalizers"]; ok {
		t.Error("finalizers must be omitted when CascadeDelete is false")
	}
}

func TestBuildApplicationSetEmptyFleet(t *testing.T) {
	p := testParams()
	p.DeployMode = types.AddonDeployModeApplicationSet
	p.Clusters = nil
	appset := buildApplicationSet(p, map[string]any{"source": gitSource(p, p.Path)})
	elements := parseDoc(t, appset)["spec"].(map[string]any)["generators"].([]any)[0].(map[string]any)["list"].(map[string]any)["elements"].([]any)
	if len(elements) != 0 {
		t.Errorf("empty fleet must render zero elements: %v", elements)
	}
}

func TestGitSourceOmitsPathForValuesRef(t *testing.T) {
	p := testParams()
	src := valuesRefSource(p)
	if _, ok := src["path"]; ok {
		t.Errorf("values ref source must not carry a path: %v", src)
	}
	if src["ref"] != "values" || src["repoURL"] != p.RepoURL {
		t.Errorf("src = %v", src)
	}
}

func TestOverlayValueFilePath(t *testing.T) {
	p := testParams()
	got := overlayValueFile(p)
	if got != "$values/clusters/{{cluster}}/cert-manager/values.yaml" {
		t.Errorf("overlay = %q", got)
	}
	if !strings.HasPrefix(baseValueFile(p), "$values/addons/cert-manager/") {
		t.Errorf("base = %q", baseValueFile(p))
	}
}
