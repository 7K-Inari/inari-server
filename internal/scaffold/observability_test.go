package scaffold

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeObservabilityTemplate(t *testing.T, kind string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "skeleton"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := "name: service\nversion: 1.4.0\nchannel: stable\ndescription: Service\nkind: " + kind + "\nobservability:\n  manifest: observability/observability.yaml\n"
	if err := os.WriteFile(filepath.Join(dir, "template.yaml"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "schema.json"), []byte(`{"type":"object"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "skeleton", "README.md"), []byte("service"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "observability"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "observability", "observability.yaml"), []byte("kind: Observability\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestTemplateObservabilityDeclarationAndPayload(t *testing.T) {
	dir := writeObservabilityTemplate(t, KindComponent)
	pkg, err := readTemplateDir(dir, "service")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := json.Marshal(pkg.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(manifest, &decoded); err != nil {
		t.Fatal(err)
	}
	obs, ok := decoded["observability"].(map[string]any)
	if !ok || obs["manifest"] != "observability/observability.yaml" {
		t.Fatalf("observability declaration lost: %s", manifest)
	}
	_, versions, err := templateSyncPlan([]TemplatePackage{*pkg})
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(versions[0].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["observabilityYaml"] != "kind: Observability\n" {
		t.Fatalf("exact template metadata missing: %#v", payload)
	}
}

func TestPureAndInvalidTemplatesDoNotProvision(t *testing.T) {
	dir := writeObservabilityTemplate(t, KindGitOpsRepo)
	if _, err := readTemplateDir(dir, "service"); err == nil {
		t.Fatal("gitops-repo template with observability was accepted")
	}
}

func TestTemplateObservabilityManifestMustExistAndBeConfined(t *testing.T) {
	dir := writeObservabilityTemplate(t, KindComponent)
	if err := os.Remove(filepath.Join(dir, "observability", "observability.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := readTemplateDir(dir, "service"); err == nil {
		t.Fatal("missing observability manifest was accepted")
	}
}
