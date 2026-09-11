package scaffold

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

// writeFixtureTemplate materializes a template package on disk:
//
//	<root>/<name>/template.yaml
//	<root>/<name>/schema.json
//	<root>/<name>/skeleton/...
func writeFixtureTemplate(t *testing.T, root, name, version string, skeleton map[string]string) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Join(dir, "skeleton"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := "name: " + name + "\nversion: " + version + "\n"
	if err := os.WriteFile(filepath.Join(dir, "template.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "schema.json"), []byte(`{"type":"object"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	for rel, content := range skeleton {
		p := filepath.Join(dir, "skeleton", filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func testRenderData() *RenderData {
	return &RenderData{
		Values: map[string]any{"name": "payments-api", "replicas": json.Number("2")},
		Tenant: TenantContext{Slug: "acme", OrgID: "org:acme", Namespace: "acme", GroupPath: "tenant-acme/members"},
		Run:    RunRef{ID: "run:1", Name: "payments-api"},
	}
}

func TestRenderSkeletonContexts(t *testing.T) {
	dir := t.TempDir()
	writeFixtureTemplate(t, dir, "go-service", "1.0.0", map[string]string{
		"README.md":            "# {{ .Values.name }}\nrun: {{ .Run.ID }} ({{ .Run.Name }})\n",
		"deploy/app.yaml.tmpl": "namespace: {{ .Tenant.Namespace }}\nslug: {{ .Tenant.Slug }}\norg: {{ .Tenant.OrgID }}\ngroup: {{ .Tenant.GroupPath }}\n",
	})
	files, err := renderSkeleton(filepath.Join(dir, "go-service"), testRenderData())
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("want 2 files, got %d", len(files))
	}
	if files[0].Path != "README.md" || files[1].Path != "deploy/app.yaml" {
		t.Fatalf("paths not sorted / .tmpl not stripped: %+v", files)
	}
	if !strings.Contains(files[0].Content, "# payments-api") || !strings.Contains(files[0].Content, "run: run:1 (payments-api)") {
		t.Fatalf("values/run context not rendered: %q", files[0].Content)
	}
	for _, want := range []string{"namespace: acme", "slug: acme", "org: org:acme", "group: tenant-acme/members"} {
		if !strings.Contains(files[1].Content, want) {
			t.Fatalf("tenant context missing %q in %q", want, files[1].Content)
		}
	}
}

func TestRenderSkeletonMissingKeyFails(t *testing.T) {
	dir := t.TempDir()
	writeFixtureTemplate(t, dir, "go-service", "1.0.0", map[string]string{
		"app.yaml": "name: {{ .Values.does_not_exist }}\n",
	})
	if _, err := renderSkeleton(filepath.Join(dir, "go-service"), testRenderData()); err == nil || !strings.Contains(err.Error(), "does_not_exist") {
		t.Fatalf("want missingkey error, got %v", err)
	}
}

func TestRenderSkeletonBinaryRejected(t *testing.T) {
	dir := t.TempDir()
	writeFixtureTemplate(t, dir, "go-service", "1.0.0", map[string]string{
		"bin.dat": string([]byte{0xff, 0xfe, 0x00, 0x01}),
	})
	if _, err := renderSkeleton(filepath.Join(dir, "go-service"), testRenderData()); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("want binary rejection, got %v", err)
	}
}

func renderStepRun(values string) *types.ScaffoldRun {
	return &types.ScaffoldRun{
		ID: "run:1", OrgID: "org:acme", TemplateItemID: "template:go-service",
		TemplateVersion: "1.0.0", DisplayName: "payments-api",
		Values: json.RawMessage(values), Phase: types.ScaffoldPhaseRendering,
	}
}

func TestStepRenderingRendersAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	writeFixtureTemplate(t, dir, "go-service", "1.0.0", map[string]string{
		"deploy/app.yaml.tmpl": "name: {{ .Values.name }}\nns: {{ .Tenant.Namespace }}\n",
	})
	env := &ExecEnv{Templates: &FilePuller{Root: dir}}
	run := renderStepRun(`{"name":"payments-api"}`)
	rc := &RunContext{Run: run, Steps: map[string]*types.ScaffoldRunStep{}, Tenant: &TenantContext{Slug: "acme", OrgID: "org:acme", Namespace: "acme", GroupPath: "tenant-acme/members"}, Actor: "dev-1"}
	step := &types.ScaffoldRunStep{RunID: run.ID, Name: "rendering", State: types.ScaffoldStepRunning, MaxAttempts: 5}

	done, err := stepRendering(context.Background(), env, rc, step)
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	var res renderResult
	if err := json.Unmarshal(step.Result, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 1 || res.Files[0].Path != "deploy/app.yaml" {
		t.Fatalf("unexpected result: %s", step.Result)
	}
	if !strings.Contains(res.Files[0].Content, "name: payments-api") || !strings.Contains(res.Files[0].Content, "ns: acme--payments-api") {
		t.Fatalf("content not rendered: %q", res.Files[0].Content)
	}
	var outputs map[string]any
	if err := json.Unmarshal(run.Outputs, &outputs); err != nil || outputs["renderedFiles"] != float64(1) {
		t.Fatalf("outputs = %s (%v)", run.Outputs, err)
	}

	// Re-entry with a persisted result short-circuits — even if the
	// template dir has since changed/broken.
	if err := os.RemoveAll(filepath.Join(dir, "go-service")); err != nil {
		t.Fatal(err)
	}
	done, err = stepRendering(context.Background(), env, rc, step)
	if err != nil || !done {
		t.Fatalf("idempotent re-entry: done=%v err=%v", done, err)
	}
}

func TestStepRenderingVersionMismatchFails(t *testing.T) {
	dir := t.TempDir()
	writeFixtureTemplate(t, dir, "go-service", "2.0.0", map[string]string{"a.txt": "x"})
	env := &ExecEnv{Templates: &FilePuller{Root: dir}}
	run := renderStepRun(`{"name":"payments-api"}`) // wants 1.0.0
	rc := &RunContext{Run: run, Steps: map[string]*types.ScaffoldRunStep{}, Actor: "dev-1"}
	step := &types.ScaffoldRunStep{RunID: run.ID, Name: "rendering", State: types.ScaffoldStepRunning}

	if _, err := stepRendering(context.Background(), env, rc, step); err == nil || !strings.Contains(err.Error(), "version 1.0.0 not found") {
		t.Fatalf("want version mismatch error, got %v", err)
	}
}

func TestStepRenderingUnknownTemplateFails(t *testing.T) {
	env := &ExecEnv{Templates: &FilePuller{Root: t.TempDir()}}
	run := renderStepRun(`{"name":"payments-api"}`)
	rc := &RunContext{Run: run, Steps: map[string]*types.ScaffoldRunStep{}, Actor: "dev-1"}
	step := &types.ScaffoldRunStep{RunID: run.ID, Name: "rendering", State: types.ScaffoldStepRunning}
	if _, err := stepRendering(context.Background(), env, rc, step); err == nil {
		t.Fatal("want error for unknown template")
	}
}

// The shipped go-service seed template must render with schema-valid
// wizard values (regression: the skeleton once referenced capitalized
// .Values keys the schema does not define, failing every run under
// missingkey=error).
func TestSeedTemplateRendersWithSchemaValidValues(t *testing.T) {
	env := &ExecEnv{Templates: &FilePuller{Root: "../../templates"}}
	run := &types.ScaffoldRun{
		ID: "run:1", OrgID: "org:acme", TemplateItemID: "template:go-service",
		TemplateVersion: "0.1.0", DisplayName: "payments-api",
		Values: json.RawMessage(`{"serviceName":"payments-api","module":"github.com/acme/payments-api","goVersion":"1.23","port":8080}`),
	}
	rc := &RunContext{Run: run, Steps: map[string]*types.ScaffoldRunStep{},
		Tenant: &TenantContext{Slug: "acme", OrgID: "org:acme", Namespace: "acme", GroupPath: "tenant-acme/members"}}
	step := &types.ScaffoldRunStep{RunID: run.ID, Name: "rendering", State: types.ScaffoldStepRunning}
	done, err := stepRendering(context.Background(), env, rc, step)
	if err != nil || !done {
		t.Fatalf("seed template must render: done=%v err=%v", done, err)
	}
	var res renderResult
	if err := json.Unmarshal(step.Result, &res); err != nil || len(res.Files) == 0 {
		t.Fatalf("render result = %s (%v)", step.Result, err)
	}
	for _, f := range res.Files {
		if strings.Contains(f.Content, "{{") {
			t.Fatalf("%s: unrendered template syntax left: %s", f.Path, f.Content)
		}
	}
}

func TestStepRenderingRejectsUnsafeTemplateName(t *testing.T) {
	dir := t.TempDir()
	writeFixtureTemplate(t, dir, "go-service", "1.0.0", map[string]string{"a.txt": "x"})
	env := &ExecEnv{Templates: &FilePuller{Root: dir}}
	for _, itemID := range []string{"template:../go-service", "template:a/b", "template:"} {
		run := renderStepRun(`{"name":"payments-api"}`)
		run.TemplateItemID = itemID
		rc := &RunContext{Run: run, Steps: map[string]*types.ScaffoldRunStep{}, Actor: "dev-1"}
		step := &types.ScaffoldRunStep{RunID: run.ID, Name: "rendering", State: types.ScaffoldStepRunning}
		if _, err := stepRendering(context.Background(), env, rc, step); err == nil || !strings.Contains(err.Error(), "invalid template name") {
			t.Fatalf("%s: want invalid template name error, got %v", itemID, err)
		}
	}
}
