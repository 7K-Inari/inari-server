package catalog

import (
	"context"
	"testing"
)

func TestFixturePuller(t *testing.T) {
	p := &FixturePuller{Root: "testdata/oci"}
	pkgs, err := p.Pull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("pulled %d packages, want 3", len(pkgs))
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
}
