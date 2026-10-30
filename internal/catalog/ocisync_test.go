package catalog

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestSyncWithoutPuller(t *testing.T) {
	s := &Service{}
	if _, err := s.Sync(context.Background()); !errors.Is(err, ErrSyncNotConfigured) {
		t.Fatalf("err = %v, want ErrSyncNotConfigured", err)
	}
}

func TestFixturePuller(t *testing.T) {
	p := &FixturePuller{Root: "testdata/oci"}
	pkgs, err := p.Pull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 4 {
		t.Fatalf("pulled %d packages, want 4", len(pkgs))
	}
	byKey := map[string]Package{}
	for _, pkg := range pkgs {
		byKey[pkg.Name+"@"+pkg.Version] = pkg
	}
	pg, ok := byKey["postgres-aws@1.1.0"]
	if !ok {
		t.Fatal("postgres-aws@1.1.0 missing")
	}
	if pg.Channel != "stable" {
		t.Errorf("channel = %q, want stable", pg.Channel)
	}
	if pg.Category != "database" {
		t.Errorf("category = %q, want database", pg.Category)
	}
	if len(pg.RGD) == 0 {
		t.Error("RGD empty")
	}
	if len(pg.Schema) == 0 {
		t.Error("schema empty")
	}
	ws, ok := byKey["web-service@0.1.0"]
	if !ok {
		t.Fatal("web-service@0.1.0 missing")
	}
	if ws.Channel != "incubating" {
		t.Errorf("channel = %q, want incubating", ws.Channel)
	}
	if ws.Category != "compute" {
		t.Errorf("category = %q, want compute", ws.Category)
	}
	// Platform-app fixture: no schema.json, so the vendored
	// values.schema.json becomes the version's values schema (decision 4).
	ed, ok := byKey["external-dns@1.15.2"]
	if !ok {
		t.Fatal("external-dns@1.15.2 missing")
	}
	if !strings.Contains(string(ed.Schema), `"upsert-only"`) {
		t.Errorf("external-dns schema = %s, want vendored values.schema.json", ed.Schema)
	}
}

// TestPackageFromFilesSchemaPrecedence pins the schema layering: an explicit
// schema.json wins over the vendored values.schema.json.
func TestPackageFromFilesSchemaPrecedence(t *testing.T) {
	files := map[string][]byte{
		"package.yaml":       []byte("version: 1.0.0\nchannel: stable\ntype: platform-app\n"),
		"chart.yaml":         []byte("repoURL: https://example.com\nchart: demo\nnamespace: demo\nchannels:\n  stable: \"1.0.0\"\n"),
		"schema.json":        []byte(`{"type":"object","properties":{"fromSchemaJson":{"type":"boolean"}}}`),
		"values.schema.json": []byte(`{"type":"object","properties":{"fromValuesSchema":{"type":"boolean"}}}`),
	}
	pkgs, err := packageFromFiles("demo", "platform-app", "", "demo:1.0.0", files)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pkgs {
		if !strings.Contains(string(p.Schema), "fromSchemaJson") {
			t.Errorf("schema = %s, want schema.json to win", p.Schema)
		}
	}
	delete(files, "schema.json")
	pkgs, err = packageFromFiles("demo", "platform-app", "", "demo:1.0.0", files)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pkgs {
		if !strings.Contains(string(p.Schema), "fromValuesSchema") {
			t.Errorf("schema = %s, want values.schema.json fallback", p.Schema)
		}
	}
}

func TestSyncPlanPersistsCategory(t *testing.T) {
	items, _, err := syncPlan([]Package{{Name: "postgres-aws", Version: "1.1.0", Category: "database"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("items = %d, want 1", len(items))
	}
	if items[0].Category != "database" {
		t.Errorf("item category = %q, want database", items[0].Category)
	}
}
