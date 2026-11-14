package catalog

import (
	"context"
	"errors"
	"strings"
	"testing"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
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
		"chart.yaml":         []byte("repoURL: oci://example.com/charts\nchart: demo\nnamespace: demo\nchannels:\n  stable:\n    version: \"1.0.0\"\n    ociRef: example.com/charts/demo:1.0.0\n    digest: sha256:52ccaee6d4dd272e54bfccda77738b42e1edf0e4a20c27e23f0b6c15d01aef79\n"),
		"schema.json":        []byte(`{"type":"object","properties":{"fromSchemaJson":{"type":"boolean"}}}`),
		"values.schema.json": []byte(`{"type":"object","properties":{"fromValuesSchema":{"type":"boolean"}}}`),
	}
	entry := trustedsource.IndexEntry{
		Name: "demo", Type: "platform-app", Version: "1.0.0", PackageVersion: "1.0.0", Channel: "stable",
		ChartRef: "oci://example.com/charts/demo:1.0.0", ChartDigest: "sha256:52ccaee6d4dd272e54bfccda77738b42e1edf0e4a20c27e23f0b6c15d01aef79",
	}
	pkgs, err := packageFromFiles(entry, "demo:1.0.0", files)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pkgs {
		if !strings.Contains(string(p.Schema), "fromSchemaJson") {
			t.Errorf("schema = %s, want schema.json to win", p.Schema)
		}
	}
	delete(files, "schema.json")
	pkgs, err = packageFromFiles(entry, "demo:1.0.0", files)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pkgs {
		if !strings.Contains(string(p.Schema), "fromValuesSchema") {
			t.Errorf("schema = %s, want values.schema.json fallback", p.Schema)
		}
	}
}

func TestPackageFromFilesBindsSignedIndexMetadata(t *testing.T) {
	entry := trustedsource.IndexEntry{
		Name: "demo", Type: "platform-app", Version: "1.0.0", PackageVersion: "1.0.0", Channel: "stable",
		ChartRef: "oci://example.com/charts/demo:1.0.0", ChartDigest: "sha256:52ccaee6d4dd272e54bfccda77738b42e1edf0e4a20c27e23f0b6c15d01aef79",
	}
	files := map[string][]byte{
		"package.yaml": []byte("version: 1.0.0\nchannel: stable\ntype: platform-app\n"),
		"chart.yaml":   []byte("repoURL: oci://example.com/charts\nchart: demo\nnamespace: demo\nchannels:\n  stable:\n    version: \"1.0.0\"\n    ociRef: example.com/charts/demo:1.0.0\n    digest: " + entry.ChartDigest + "\n  incubating:\n    version: \"1.0.0\"\n    ociRef: example.com/charts/demo:1.0.0\n    digest: " + entry.ChartDigest + "\n"),
	}
	pkgs, err := packageFromFiles(entry, "example.com/catalog/demo@sha256:package", files)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].Channel != "stable" {
		t.Fatalf("packages = %+v, want only the signed stable entry", pkgs)
	}
	if pkgs[0].Chart.OCIRef != entry.ChartRef || pkgs[0].Chart.Digest != entry.ChartDigest {
		t.Fatalf("chart = %+v, want signed index coordinates", pkgs[0].Chart)
	}

	for _, tc := range []struct {
		name   string
		mutate func()
	}{
		{"type", func() { files["package.yaml"] = []byte("version: 1.0.0\nchannel: stable\ntype: kro-rgd\n") }},
		{"package version", func() { files["package.yaml"] = []byte("version: 2.0.0\nchannel: stable\ntype: platform-app\n") }},
		{"channel", func() { files["package.yaml"] = []byte("version: 1.0.0\nchannel: edge\ntype: platform-app\n") }},
		{"chart digest", func() {
			files["chart.yaml"] = []byte("repoURL: oci://example.com/charts\nchart: demo\nnamespace: demo\nchannels:\n  stable:\n    version: \"1.0.0\"\n    ociRef: example.com/charts/demo:1.0.0\n    digest: sha256:0000000000000000000000000000000000000000000000000000000000000000\n")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files["package.yaml"] = []byte("version: 1.0.0\nchannel: stable\ntype: platform-app\n")
			files["chart.yaml"] = []byte("repoURL: oci://example.com/charts\nchart: demo\nnamespace: demo\nchannels:\n  stable:\n    version: \"1.0.0\"\n    ociRef: example.com/charts/demo:1.0.0\n    digest: " + entry.ChartDigest + "\n  incubating:\n    version: \"1.0.0\"\n    ociRef: example.com/charts/demo:1.0.0\n    digest: " + entry.ChartDigest + "\n")
			tc.mutate()
			if _, err := packageFromFiles(entry, "example.com/catalog/demo@sha256:package", files); err == nil {
				t.Fatal("expected signed index/package mismatch to fail")
			}
		})
	}
}

func TestSyncPlanPersistsCategory(t *testing.T) {
	items, _, err := syncPlan("core", []Package{{Name: "postgres-aws", Version: "1.1.0", Category: "database"}})
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
