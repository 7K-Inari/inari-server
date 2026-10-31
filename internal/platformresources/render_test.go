package platformresources

import (
	"context"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// fakeTenantLookup resolves orgs by ID (tenancy.Service seam).
type fakeTenantLookup struct{ org *types.Organization }

func (f fakeTenantLookup) GetTenantByID(context.Context, string) (*types.Organization, error) {
	return f.org, nil
}

func renderSvc() *Service {
	return NewService(nil, nil, nil)
}

func testOrg() *types.Organization {
	return &types.Organization{ID: "org:kc-123", Slug: "acme", DisplayName: "Acme Corp"}
}

func filesByPath(files []gitprovider.File) map[string]string {
	out := map[string]string{}
	for _, f := range files {
		out[f.Path] = string(f.Content)
	}
	return out
}

func parseYAML(t *testing.T, content string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		t.Fatalf("parse %q: %v", content, err)
	}
	return doc
}

func TestRenderTenantFilesDescriptors(t *testing.T) {
	s := renderSvc()
	repoURL := "https://fake.git/inari/platform.git"
	files, err := s.RenderTenantFiles(context.Background(), testOrg(), repoURL)
	if err != nil {
		t.Fatal(err)
	}
	byPath := filesByPath(files)
	wantPaths := []string{
		"tenants/acme/project/application.yaml",
		"tenants/acme/project/manifests/00-appproject-tenant-acme.yaml",
		"tenants/acme/dns/application.yaml",
		"tenants/acme/dns/manifests/00-dnsendpoint-acme.yaml",
		"tenants/acme/namespace/application.yaml",
		"tenants/acme/namespace/instance.yaml",
		"tenants/acme/keycloak/realm/application.yaml",
		"tenants/acme/keycloak/realm/manifests/00-tenantrealm-acme.yaml",
	}
	for _, p := range wantPaths {
		if _, ok := byPath[p]; !ok {
			t.Errorf("missing %s (has %v)", p, byPath)
		}
	}

	// AppProject: destination restriction + dex repo auto-union.
	project := parseYAML(t, byPath["tenants/acme/project/manifests/00-appproject-tenant-acme.yaml"])
	if project["kind"] != "AppProject" {
		t.Errorf("kind = %v", project["kind"])
	}
	spec := project["spec"].(map[string]any)
	repos := spec["sourceRepos"].([]any)
	if len(repos) != 2 || repos[0] != repoURL || repos[1] != "https://charts.dexidp.io" {
		t.Errorf("sourceRepos = %v, want [repoURL + dex union]", repos)
	}
	dests := spec["destinations"].([]any)
	if len(dests) != 1 || dests[0].(map[string]any)["namespace"] != "tenant-acme" {
		t.Errorf("destinations = %v, want tenant-acme only", dests)
	}

	// DNSEndpoint: native ExternalDNS resource replacing the DNSRecord CR.
	dns := parseYAML(t, byPath["tenants/acme/dns/manifests/00-dnsendpoint-acme.yaml"])
	if dns["apiVersion"] != "externaldns.k8s.io/v1alpha1" || dns["kind"] != "DNSEndpoint" {
		t.Errorf("dns doc = %v/%v", dns["apiVersion"], dns["kind"])
	}
	eps := dns["spec"].(map[string]any)["endpoints"].([]any)
	ep := eps[0].(map[string]any)
	if ep["dnsName"] != "tenant-acme.7kgroup.org" || ep["recordType"] != "CNAME" {
		t.Errorf("endpoint = %v", ep)
	}

	// KRO instance: coordinates come from the RGD (stacks.inari.io/v1alpha1).
	inst := parseYAML(t, byPath["tenants/acme/namespace/instance.yaml"])
	if inst["apiVersion"] != "stacks.inari.io/v1alpha1" || inst["kind"] != "TenantNamespace" {
		t.Errorf("instance = %v/%v", inst["apiVersion"], inst["kind"])
	}
	ispec := inst["spec"].(map[string]any)
	if ispec["tenantID"] != "acme" || ispec["namespace"] != "tenant-acme" {
		t.Errorf("instance spec = %v", ispec)
	}

	// TenantRealm claim: hub-side, tenant-scoped path.
	realm := parseYAML(t, byPath["tenants/acme/keycloak/realm/manifests/00-tenantrealm-acme.yaml"])
	if realm["apiVersion"] != "identity.inari.io/v1alpha1" || realm["kind"] != "TenantRealm" {
		t.Errorf("realm = %v/%v", realm["apiVersion"], realm["kind"])
	}
	rspec := realm["spec"].(map[string]any)
	if rspec["tenantID"] != "acme" || rspec["namespace"] != "tenant-acme" || rspec["displayName"] != "Acme Corp" {
		t.Errorf("realm spec = %v", rspec)
	}

	// Applications carry the repo URL + tenant project / destination.
	app := parseYAML(t, byPath["tenants/acme/dns/application.yaml"])
	aspec := app["spec"].(map[string]any)
	if aspec["project"] != "tenant-acme" {
		t.Errorf("dns app project = %v", aspec["project"])
	}
	src := aspec["source"].(map[string]any)
	if src["repoURL"] != repoURL || src["path"] != "tenants/acme/dns/manifests" {
		t.Errorf("dns app source = %v", src)
	}
	if app["metadata"].(map[string]any)["namespace"] != "argocd" {
		t.Errorf("app namespace = %v", app["metadata"])
	}

	// Deterministic.
	again, err := s.RenderTenantFiles(context.Background(), testOrg(), repoURL)
	if err != nil {
		t.Fatal(err)
	}
	for i := range files {
		if string(files[i].Content) != string(again[i].Content) || files[i].Path != again[i].Path {
			t.Errorf("render %d not deterministic", i)
		}
	}
}

func TestZoneContainment(t *testing.T) {
	for _, tc := range []struct {
		name, zone string
		want       bool
	}{
		{"tenant-acme.7kgroup.org", "7kgroup.org", true},
		{"7kgroup.org", "7kgroup.org", true},
		{"a.b.7kgroup.org.", "7kgroup.org.", true},
		{"evil-example.com", "7kgroup.org", false},
		{"not7kgroup.org", "7kgroup.org", false},
	} {
		if got := dnsNamesInZone(tc.name, tc.zone); got != tc.want {
			t.Errorf("dnsNamesInZone(%q, %q) = %v, want %v", tc.name, tc.zone, got, tc.want)
		}
	}
	err := validateZoneContainment([]dnsEndpoint{{DNSName: "x.example.com"}}, sharedDNSZone)
	if err == nil || !strings.Contains(err.Error(), "outside zone") {
		t.Errorf("validateZoneContainment: err = %v", err)
	}
	if err := validateZoneContainment(tenantDNSEndpoints(testOrg()), sharedDNSZone); err != nil {
		t.Errorf("tenant endpoints must validate: %v", err)
	}
}

func TestUnionSourceRepos(t *testing.T) {
	got := unionSourceRepos([]string{"https://fake.git/r.git"})
	if len(got) != 2 || got[1] != dexChartRepoURL {
		t.Errorf("union = %v", got)
	}
	// Idempotent: no duplicate when already present.
	got = unionSourceRepos([]string{"https://fake.git/r.git", dexChartRepoURL})
	if len(got) != 2 {
		t.Errorf("union with existing dex repo = %v", got)
	}
}

func TestTenantIssuerURL(t *testing.T) {
	got := tenantIssuerURL("http://keycloak/realms/inari", "acme")
	if got != "http://keycloak/realms/acme" {
		t.Errorf("issuer = %q", got)
	}
	if got := tenantIssuerURL("http://keycloak/realms/inari/", "acme"); got != "http://keycloak/realms/acme" {
		t.Errorf("trailing slash: issuer = %q", got)
	}
	// Path-less issuer gets the realms suffix (not a mangled host).
	if got := tenantIssuerURL("https://keycloak.example.com", "acme"); got != "https://keycloak.example.com/realms/acme" {
		t.Errorf("path-less issuer = %q", got)
	}
}

func TestTenantRenderPaths(t *testing.T) {
	paths, err := renderSvc().TenantRenderPaths(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	// The 8 tenant-level descriptor paths (client claims are unwired here).
	if len(paths) != 8 {
		t.Errorf("paths = %v, want 8 descriptor paths", paths)
	}
	// D7: no legacy platform.inari.io CR paths in the teardown set.
	for _, p := range paths {
		if strings.HasSuffix(p, "keycloak-realm.yaml") || strings.HasSuffix(p, "dns-record.yaml") ||
			strings.HasSuffix(p, "tenant-namespace.yaml") {
			t.Errorf("legacy CR path %q must not be in the delete set", p)
		}
	}
}

func TestRenderKeycloakClientClaim(t *testing.T) {
	org := testOrg()
	git := gitprovider.NewFake()
	s := renderSvc().
		WithGitOps("inari/platform", git).
		WithTenantLookup(fakeTenantLookup{org: org})

	// clientID carries an uppercase ULID; the claim name lowercases it.
	clientID := "cluster-01JFXM6E8BM0G52GQPMNWP2ZC0"
	rendered, err := s.RenderKeycloakClientClaim(context.Background(), org.ID, "01JFXM6E8BM0G52GQPMNWP2ZC0", clientID,
		"http://keycloak/realms/inari")
	if err != nil {
		t.Fatal(err)
	}
	if !rendered {
		t.Fatal("expected rendered=true")
	}
	claimName := strings.ToLower(clientID)
	files := git.Files("inari/platform", "main")
	byPath := map[string]string{}
	for p, c := range files {
		byPath[p] = c
	}
	base := "tenants/acme/keycloak/client-" + claimName + "/"
	for _, p := range []string{
		base + "application.yaml",
		base + "manifests/00-serviceaccount-eso-tenant-secret-reader.yaml",
		base + "manifests/03-secretstore-keycloak-client-connections.yaml",
		base + "manifests/04-tenantclient-" + claimName + ".yaml",
		base + "manifests/05-externalsecret-" + claimName + "-keycloak-client.yaml",
	} {
		if _, ok := byPath[p]; !ok {
			t.Errorf("missing %s (has %v)", p, byPath)
		}
	}
	claim := parseYAML(t, byPath[base+"manifests/04-tenantclient-"+claimName+".yaml"])
	cspec := claim["spec"].(map[string]any)
	if cspec["clientID"] != clientID || cspec["realm"] != "acme" || cspec["namespace"] != "tenant-acme" {
		t.Errorf("claim spec = %v", cspec)
	}
	if claim["metadata"].(map[string]any)["name"] != claimName {
		t.Errorf("claim name = %v, want lowercased %s", claim["metadata"], claimName)
	}
	es := parseYAML(t, byPath[base+"manifests/05-externalsecret-"+claimName+"-keycloak-client.yaml"])
	tmpl := es["spec"].(map[string]any)["target"].(map[string]any)["template"].(map[string]any)["data"].(map[string]any)
	if tmpl["issuer"] != "http://keycloak/realms/acme" || tmpl["client-id"] != clientID {
		t.Errorf("externalsecret template data = %v", tmpl)
	}

	// ESO v1 schema: caProvider nests under server — a top-level
	// kubernetes.caProvider is rejected by strict decoding (caught live by
	// the renderpath e2e).
	ss := parseYAML(t, byPath[base+"manifests/03-secretstore-keycloak-client-connections.yaml"])
	k8s := ss["spec"].(map[string]any)["provider"].(map[string]any)["kubernetes"].(map[string]any)
	if _, bad := k8s["caProvider"]; bad {
		t.Error("caProvider must nest under server (ESO strict decoding rejects kubernetes.caProvider)")
	}
	server, ok := k8s["server"].(map[string]any)
	if !ok || server["caProvider"] == nil {
		t.Errorf("server.caProvider missing in SecretStore: %v", k8s)
	}
	// A namespaced SecretStore forbids caProvider.namespace (ESO admission:
	// the store implicitly reads its own namespace).
	if cap_, _ := server["caProvider"].(map[string]any); cap_["namespace"] != nil {
		t.Errorf("namespaced SecretStore must not set caProvider.namespace: %v", cap_)
	}
	// ESO's kubernetes provider schema DEFAULTS remoteNamespace to "default"
	// — the store must pin the tenant namespace or reads target the wrong
	// namespace and fail RBAC.
	if k8s["remoteNamespace"] != "tenant-acme" {
		t.Errorf("remoteNamespace = %v, want tenant-acme (ESO schema default is \"default\")", k8s["remoteNamespace"])
	}

	// Idempotent re-render (registration retry): same content, no error.
	if _, err := s.RenderKeycloakClientClaim(context.Background(), org.ID, "01JFXM6E8BM0G52GQPMNWP2ZC0", clientID,
		"http://keycloak/realms/inari"); err != nil {
		t.Fatalf("retry: %v", err)
	}
}

func TestRenderKeycloakClientClaimUnwired(t *testing.T) {
	// Git unwired → rendered=false (no repo to commit to).
	rendered, err := renderSvc().RenderKeycloakClientClaim(context.Background(), "org:kc-123", "c1", "cluster-c1", "iss")
	if err != nil || rendered {
		t.Errorf("unwired git: rendered=%v err=%v", rendered, err)
	}
}

func TestKindForCRDRenderedKinds(t *testing.T) {
	for kind, want := range map[string]types.PlatformResourceKind{
		"TenantRealm.identity.inari.io":   types.PlatformKindKeycloakRealm,
		"TenantClient.identity.inari.io":  types.PlatformKindKeycloakClient,
		"DNSEndpoint.externaldns.k8s.io":  types.PlatformKindDNSZone,
		"TenantNamespace.stacks.inari.io": types.PlatformKindTenantNamespace,
	} {
		got, ok := KindForCRD(kind)
		if !ok || got != want {
			t.Errorf("KindForCRD(%q) = %q, %v; want %q", kind, got, ok, want)
		}
		if !IsPlatformKind(kind) {
			t.Errorf("IsPlatformKind(%q) = false", kind)
		}
	}
	// Legacy platform.inari.io kinds no longer route (D7 — the CRDs are
	// gone); unknown kinds are rejected.
	if _, ok := KindForCRD("KeycloakRealm.platform.inari.io"); ok {
		t.Error("legacy KeycloakRealm kind must not route")
	}
	if IsPlatformKind("KeycloakRealm.platform.inari.io") {
		t.Error("legacy KeycloakRealm kind must not be a platform kind")
	}
	if IsPlatformKind("Deployment.apps") {
		t.Error("Deployment.apps must not be a platform kind")
	}
}
