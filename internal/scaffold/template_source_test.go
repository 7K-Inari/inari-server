package scaffold

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

// writeTemplate scaffolds a minimal valid template dir under root/name,
// applying mutators for the failure cases.
func writeTemplate(t *testing.T, root, name string, mutate func(dir string)) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Join(dir, "skeleton", "k8s"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := "name: " + name + "\n" +
		"displayName: Go Service\n" +
		"description: A Go HTTP service\n" +
		"tags: [go, service]\n" +
		"version: 0.1.0\n" +
		"channel: stable\n" +
		"scaffold:\n" +
		"  createRepo:\n" +
		"    visibility: private\n"
	if err := os.WriteFile(filepath.Join(dir, "template.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "schema.json"), []byte(`{"type":"object"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "skeleton", "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "skeleton", "k8s", "deployment.yaml"), []byte("kind: Deployment\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(dir)
	}
	return dir
}

func TestFilePullerPullsValidTemplates(t *testing.T) {
	root := t.TempDir()
	writeTemplate(t, root, "go-service", func(dir string) {
		if err := os.WriteFile(filepath.Join(dir, "uiSchema.json"), []byte(`{"ui:order":["serviceName"]}`), 0o644); err != nil {
			t.Fatal(err)
		}
	})
	writeTemplate(t, root, "python-service", nil)

	pkgs, err := (&FilePuller{Root: root}).Pull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("pulled %d packages, want 2", len(pkgs))
	}
	byName := map[string]TemplatePackage{}
	for _, p := range pkgs {
		byName[p.Manifest.Name] = p
	}
	goSvc := byName["go-service"]
	if goSvc.Manifest.DisplayName != "Go Service" || goSvc.Manifest.Version != "0.1.0" || goSvc.Manifest.Channel != "stable" {
		t.Errorf("unexpected manifest: %+v", goSvc.Manifest)
	}
	if len(goSvc.Manifest.Tags) != 2 || goSvc.Manifest.Tags[0] != "go" {
		t.Errorf("tags = %v", goSvc.Manifest.Tags)
	}
	if goSvc.Manifest.Scaffold["createRepo"]["visibility"] != "private" {
		t.Errorf("scaffold block = %v", goSvc.Manifest.Scaffold)
	}
	if string(goSvc.Schema) != `{"type":"object"}` {
		t.Errorf("schema = %s", goSvc.Schema)
	}
	if len(goSvc.UIHints) == 0 {
		t.Error("uiSchema.json should populate UIHints")
	}
	if !strings.HasPrefix(goSvc.SkeletonDigest, "sha256:") {
		t.Errorf("digest = %q", goSvc.SkeletonDigest)
	}
	// uiSchema optional: python-service has none.
	if len(byName["python-service"].UIHints) != 0 {
		t.Error("UIHints should be empty when uiSchema.json absent")
	}
	// Deterministic order (sorted by dir name).
	if pkgs[0].Manifest.Name != "go-service" || pkgs[1].Manifest.Name != "python-service" {
		t.Errorf("order = %s, %s", pkgs[0].Manifest.Name, pkgs[1].Manifest.Name)
	}
}

func TestFilePullerDefaults(t *testing.T) {
	root := t.TempDir()
	writeTemplate(t, root, "svc", func(dir string) {
		// Manifest without name (defaults to dir) and channel (defaults stable).
		manifest := "displayName: Svc\nversion: 1.0.0\n"
		if err := os.WriteFile(filepath.Join(dir, "template.yaml"), []byte(manifest), 0o644); err != nil {
			t.Fatal(err)
		}
	})
	pkgs, err := (&FilePuller{Root: root}).Pull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pkgs[0].Manifest.Name != "svc" {
		t.Errorf("name = %q, want dir default", pkgs[0].Manifest.Name)
	}
	if pkgs[0].Manifest.Channel != "stable" {
		t.Errorf("channel = %q, want stable", pkgs[0].Manifest.Channel)
	}
}

func TestFilePullerValidation(t *testing.T) {
	cases := map[string]func(dir string){
		"missing template.yaml": func(dir string) {
			_ = os.Remove(filepath.Join(dir, "template.yaml"))
		},
		"invalid manifest yaml": func(dir string) {
			_ = os.WriteFile(filepath.Join(dir, "template.yaml"), []byte(":\n- bad"), 0o644)
		},
		"missing version": func(dir string) {
			_ = os.WriteFile(filepath.Join(dir, "template.yaml"), []byte("name: x\n"), 0o644)
		},
		"manifest name differs from directory": func(dir string) {
			_ = os.WriteFile(filepath.Join(dir, "template.yaml"), []byte("name: other-svc\nversion: 0.1.0\n"), 0o644)
		},
		"invalid schema.json": func(dir string) {
			_ = os.WriteFile(filepath.Join(dir, "schema.json"), []byte("{nope"), 0o644)
		},
		"invalid uiSchema.json": func(dir string) {
			_ = os.WriteFile(filepath.Join(dir, "uiSchema.json"), []byte("{nope"), 0o644)
		},
		"missing skeleton": func(dir string) {
			_ = os.RemoveAll(filepath.Join(dir, "skeleton"))
		},
		"empty skeleton": func(dir string) {
			_ = os.RemoveAll(filepath.Join(dir, "skeleton"))
			_ = os.Mkdir(filepath.Join(dir, "skeleton"), 0o755)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeTemplate(t, root, "svc", mutate)
			_, err := (&FilePuller{Root: root}).Pull(context.Background())
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), "svc") {
				t.Errorf("error should name the template dir: %v", err)
			}
		})
	}
}

func TestFilePullerMissingRoot(t *testing.T) {
	_, err := (&FilePuller{Root: filepath.Join(t.TempDir(), "nope")}).Pull(context.Background())
	if err == nil {
		t.Fatal("expected error for missing root")
	}
}

func TestSkeletonDigestDeterministic(t *testing.T) {
	root := t.TempDir()
	writeTemplate(t, root, "a", nil)
	writeTemplate(t, root, "b", nil)
	pkgs, err := (&FilePuller{Root: root}).Pull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pkgs[0].SkeletonDigest != pkgs[1].SkeletonDigest {
		t.Error("identical trees must digest identically")
	}
	// Change one file: digest must change.
	if err := os.WriteFile(filepath.Join(root, "b", "skeleton", "main.go"), []byte("package main // changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pkgs2, err := (&FilePuller{Root: root}).Pull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pkgs2[0].SkeletonDigest == pkgs2[1].SkeletonDigest {
		t.Error("changed tree must change digest")
	}
}

func TestTemplateSyncPlan(t *testing.T) {
	root := t.TempDir()
	writeTemplate(t, root, "go-service", nil)
	pkgs, err := (&FilePuller{Root: root}).Pull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	items, versions, err := templateSyncPlan(pkgs)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || len(versions) != 1 {
		t.Fatalf("got %d items, %d versions", len(items), len(versions))
	}
	item, ver := items[0], versions[0]
	if item.ID != "template:go-service" {
		t.Errorf("item ID = %q", item.ID)
	}
	if item.Source != types.CatalogSourceTemplate {
		t.Errorf("source = %q", item.Source)
	}
	if !strings.HasPrefix(item.OCIRef, "file://") || !strings.HasSuffix(item.OCIRef, ":0.1.0") {
		t.Errorf("ociRef = %q", item.OCIRef)
	}
	if ver.ItemID != item.ID || ver.Version != "0.1.0" || ver.Channel != "stable" {
		t.Errorf("version = %+v", ver)
	}
	if string(ver.Schema) != `{"type":"object"}` {
		t.Errorf("schema = %s", ver.Schema)
	}
	var payload map[string]any
	if err := json.Unmarshal(ver.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["skeletonDigest"] != pkgs[0].SkeletonDigest {
		t.Errorf("payload digest = %v", payload["skeletonDigest"])
	}
	manifest, ok := payload["manifest"].(map[string]any)
	if !ok {
		t.Fatalf("payload manifest missing: %s", ver.Payload)
	}
	if manifest["name"] != "go-service" {
		t.Errorf("manifest name = %v", manifest["name"])
	}
	if _, ok := manifest["scaffold"].(map[string]any)["createRepo"]; !ok {
		t.Errorf("manifest scaffold block = %v", manifest["scaffold"])
	}
}

type fakeUpserter struct {
	items    []*types.CatalogItem
	versions []*types.CatalogItemVersion
	err      error
}

func (f *fakeUpserter) UpsertItem(_ context.Context, item *types.CatalogItem, version *types.CatalogItemVersion) error {
	if f.err != nil {
		return f.err
	}
	f.items = append(f.items, item)
	f.versions = append(f.versions, version)
	return nil
}

func TestSyncTemplates(t *testing.T) {
	root := t.TempDir()
	writeTemplate(t, root, "go-service", nil)
	writeTemplate(t, root, "python-service", nil)

	up := &fakeUpserter{}
	n, err := SyncTemplates(context.Background(), &FilePuller{Root: root}, up)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || len(up.items) != 2 {
		t.Fatalf("synced %d (upserts %d), want 2", n, len(up.items))
	}
	if up.items[0].ID != "template:go-service" || up.items[1].ID != "template:python-service" {
		t.Errorf("ids = %s, %s", up.items[0].ID, up.items[1].ID)
	}

	// Error propagation: partial count + error.
	boom := errors.New("db down")
	up2 := &fakeUpserter{err: boom}
	if _, err := SyncTemplates(context.Background(), &FilePuller{Root: root}, up2); !errors.Is(err, boom) {
		t.Errorf("err = %v, want %v", err, boom)
	}
}

// TestSeedTemplatesPullCleanly guards the repo-shipped templates/ dir: every
// seed template must parse, validate, and map without error.
func TestSeedTemplatesPullCleanly(t *testing.T) {
	root := filepath.Join("..", "..", "templates")
	if _, err := os.Stat(root); err != nil {
		t.Skip("templates/ seed dir not present")
	}
	pkgs, err := (&FilePuller{Root: root}).Pull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) == 0 {
		t.Fatal("no seed templates found")
	}
	if _, _, err := templateSyncPlan(pkgs); err != nil {
		t.Fatal(err)
	}
}
