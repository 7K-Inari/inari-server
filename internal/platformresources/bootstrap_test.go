package platformresources

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestBaseResourceSpecs(t *testing.T) {
	org := &types.Organization{ID: "org:kc-123", Slug: "acme", KeycloakOrgID: "kc-123"}
	specs := baseResourceSpecs(org)
	if len(specs) != 3 {
		t.Fatalf("baseResourceSpecs returned %d specs, want 3", len(specs))
	}
	byKind := map[types.PlatformResourceKind]resourceSpec{}
	for _, s := range specs {
		if s.orgID != org.ID {
			t.Errorf("spec %s orgID = %q, want %q", s.kind, s.orgID, org.ID)
		}
		byKind[s.kind] = s
	}

	realm, ok := byKind[types.PlatformKindKeycloakRealm]
	if !ok {
		t.Fatal("missing keycloak-realm spec")
	}
	if realm.name != "acme" {
		t.Errorf("keycloak-realm name = %q, want %q", realm.name, "acme")
	}
	var realmDesired map[string]string
	if err := json.Unmarshal(realm.desired, &realmDesired); err != nil {
		t.Fatalf("keycloak-realm desired: %v", err)
	}
	if realmDesired["realm"] != "inari" || realmDesired["organization"] != "acme" {
		t.Errorf("keycloak-realm desired = %v", realmDesired)
	}

	dns, ok := byKind[types.PlatformKindDNSZone]
	if !ok {
		t.Fatal("missing dns-zone spec")
	}
	if dns.name != "acme" {
		t.Errorf("dns-zone name = %q, want %q", dns.name, "acme")
	}
	var dnsDesired map[string]string
	if err := json.Unmarshal(dns.desired, &dnsDesired); err != nil {
		t.Fatalf("dns-zone desired: %v", err)
	}
	if dnsDesired["mode"] != "shared-record" {
		t.Errorf("dns-zone desired = %v, want mode=shared-record", dnsDesired)
	}

	ns, ok := byKind[types.PlatformKindTenantNamespace]
	if !ok {
		t.Fatal("missing tenant-namespace spec")
	}
	if ns.name != "tenant-acme" {
		t.Errorf("tenant-namespace name = %q, want %q", ns.name, "tenant-acme")
	}
	var nsDesired map[string]string
	if err := json.Unmarshal(ns.desired, &nsDesired); err != nil {
		t.Fatalf("tenant-namespace desired: %v", err)
	}
	if nsDesired["namespace"] != "tenant-acme" {
		t.Errorf("tenant-namespace desired = %v", nsDesired)
	}
}

func TestRenderTenantManifests(t *testing.T) {
	org := &types.Organization{ID: "org:kc-123", Slug: "acme"}
	files := RenderTenantManifests(org)
	if len(files) != 3 {
		t.Fatalf("RenderTenantManifests returned %d files, want 3", len(files))
	}
	wantPaths := []string{
		"tenants/acme/keycloak-realm.yaml",
		"tenants/acme/dns-record.yaml",
		"tenants/acme/tenant-namespace.yaml",
	}
	wantKinds := []string{"KeycloakRealm", "DNSRecord", "TenantNamespace"}
	for i, f := range files {
		if f.Path != wantPaths[i] {
			t.Errorf("file %d path = %q, want %q", i, f.Path, wantPaths[i])
		}
		c := string(f.Content)
		for _, want := range []string{
			"apiVersion: inari.7k.io/v1alpha1",
			"kind: " + wantKinds[i],
			"name: ",
			"inari.7k.io/org: org:kc-123",
			"acme",
		} {
			if !strings.Contains(c, want) {
				t.Errorf("%s missing %q:\n%s", f.Path, want, c)
			}
		}
	}
	if !strings.Contains(string(files[1].Content), "mode: shared-record") {
		t.Errorf("dns-record manifest must use the shared-zone model:\n%s", files[1].Content)
	}
	// Deterministic: same input renders byte-identical output.
	again := RenderTenantManifests(org)
	for i := range files {
		if string(files[i].Content) != string(again[i].Content) {
			t.Errorf("render %d not deterministic", i)
		}
	}
}
