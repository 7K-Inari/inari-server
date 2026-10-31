package clusterdex

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func dig(t *testing.T, m map[string]any, path ...string) any {
	t.Helper()
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("path %v: %v is not a map", path, cur)
		}
		next, ok := mm[p]
		if !ok {
			t.Fatalf("path %v: key %q missing", path, p)
		}
		cur = next
	}
	return cur
}

func parseValues(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var v map[string]any
	if err := yaml.Unmarshal(raw, &v); err != nil {
		t.Fatalf("values are not valid YAML: %v\n%s", err, raw)
	}
	return v
}

// --- AppName (ported from the operator's tenantChildName("dex", clusterID)) ---

func TestAppName(t *testing.T) {
	if got := AppName("c1"); got != "dex-c1" {
		t.Errorf("AppName(c1) = %q", got)
	}
	// Typed server IDs ("cluster:<uuid>") are trimmed to a DNS-safe name.
	if got := AppName("cluster:abc-123"); got != "dex-abc-123" {
		t.Errorf("AppName(cluster:abc-123) = %q", got)
	}
	if AppName("c1") != AppName("c1") {
		t.Fatal("AppName must be deterministic")
	}
	if AppName("c1") == AppName("c2") {
		t.Fatal("AppName must differ per cluster")
	}
}

func TestAppNameTruncatesLongIDs(t *testing.T) {
	long := strings.Repeat("a", 70)
	got := AppName(long)
	if len(got) > 63 {
		t.Fatalf("AppName len = %d (> 63, invalid DNS label)", len(got))
	}
	if !strings.HasPrefix(got, "dex-") {
		t.Errorf("AppName = %q, want dex- prefix", got)
	}
	// Same hash suffix contract as the operator: sha256 content hash.
	if AppName(long) != AppName(long) {
		t.Fatal("truncated name must be deterministic")
	}
	if AppName(long) == AppName(long+"b") {
		t.Fatal("hash suffix must keep truncated names unique")
	}
}

func TestDefaultIssuerURL(t *testing.T) {
	got := DefaultIssuerURL("c1")
	if got != "http://dex-c1.dex.svc.cluster.local:5556/dex" {
		t.Errorf("DefaultIssuerURL(c1) = %q", got)
	}
	if DefaultIssuerURL("c1") == DefaultIssuerURL("c2") {
		t.Fatal("issuer must differ per cluster")
	}
	// Long IDs stay DNS-valid (operator contract).
	host := strings.TrimPrefix(DefaultIssuerURL(strings.Repeat("a", 63)), "http://")
	if label := strings.SplitN(host, ".", 2)[0]; len(label) > 63 {
		t.Fatalf("issuer host label %q exceeds 63 chars", label)
	}
}

// --- Dex base values (operator's dexHelmValues hardening baseline) ---

func TestDexBaseValuesHardening(t *testing.T) {
	v := parseValues(t, mustValuesYAML(dexBaseValues(Config{})))

	if got := dig(t, v, "commonLabels", "app.kubernetes.io/part-of"); got != "inari-platform" {
		t.Errorf("part-of label = %v", got)
	}
	if got := dig(t, v, "service", "ports", "http", "port"); got != 5556 {
		t.Errorf("service http port = %v (issuer assumes 5556)", got)
	}
	if got := dig(t, v, "networkPolicy", "enabled"); got != true {
		t.Errorf("networkPolicy.enabled = %v", got)
	}
	raw, _ := yaml.Marshal(dig(t, v, "networkPolicy", "egressRules"))
	for _, want := range []string{"port: 53", "port: 443"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("egressRules missing %s:\n%s", want, raw)
		}
	}
	if got := dig(t, v, "podDisruptionBudget", "enabled"); got != true {
		t.Errorf("pdb.enabled = %v", got)
	}
	if got := dig(t, v, "podDisruptionBudget", "minAvailable"); got != 1 {
		t.Errorf("pdb.minAvailable = %v", got)
	}
	psc := dig(t, v, "podSecurityContext").(map[string]any)
	if psc["runAsNonRoot"] != true || psc["runAsUser"] != 1001 || psc["runAsGroup"] != 1001 || psc["fsGroup"] != 1001 {
		t.Errorf("podSecurityContext = %+v", psc)
	}
	if got := dig(t, psc, "seccompProfile", "type"); got != "RuntimeDefault" {
		t.Errorf("seccompProfile = %v", got)
	}
	sc := dig(t, v, "securityContext").(map[string]any)
	if sc["allowPrivilegeEscalation"] != false || sc["readOnlyRootFilesystem"] != true {
		t.Errorf("securityContext = %+v", sc)
	}
	if got := dig(t, sc, "capabilities", "drop"); got == nil {
		t.Error("capabilities.drop missing")
	}
	if got := dig(t, v, "resources", "requests", "cpu"); got != "50m" {
		t.Errorf("resources.requests.cpu = %v", got)
	}
	if got := dig(t, v, "resources", "requests", "memory"); got != "64Mi" {
		t.Errorf("resources.requests.memory = %v", got)
	}
	if got := dig(t, v, "resources", "limits", "memory"); got != "128Mi" {
		t.Errorf("resources.limits.memory = %v", got)
	}
}

func TestDexBaseValuesNoPerClusterKeys(t *testing.T) {
	v := parseValues(t, mustValuesYAML(dexBaseValues(Config{})))
	for _, key := range []string{"fullnameOverride", "configSecret", "config", "httpRoute"} {
		if _, ok := v[key]; ok {
			t.Errorf("base values must not carry per-cluster key %q", key)
		}
	}
}

func TestDexBaseValuesImageOverride(t *testing.T) {
	v := parseValues(t, mustValuesYAML(dexBaseValues(Config{DexImage: "ghcr.io/dexidp/dex:v2.42.0"})))
	if got := dig(t, v, "image", "repository"); got != "ghcr.io/dexidp/dex" {
		t.Errorf("image.repository = %v", got)
	}
	if got := dig(t, v, "image", "tag"); got != "v2.42.0" {
		t.Errorf("image.tag = %v", got)
	}
}

func TestDexBaseValuesImageOverrideEdgeCases(t *testing.T) {
	for _, tc := range []struct {
		name    string
		image   string
		wantErr bool
	}{
		{"registry port", "host:5000/dexidp/dex:v2.42.0", false},
		{"missing tag", "ghcr.io/dexidp/dex", true},
		{"digest ref", "ghcr.io/dexidp/dex@sha256:1a2b3c", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := dexBaseValues(Config{DexImage: tc.image})
			if tc.wantErr && err == nil {
				t.Fatalf("image %q: expected error, got none", tc.image)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("image %q: unexpected error %v", tc.image, err)
			}
		})
	}
}

// --- Per-cluster overlays ---

func TestDexOverlay(t *testing.T) {
	v := parseValues(t, mustValuesYAML(dexOverlay("c1")))
	if got := dig(t, v, "fullnameOverride"); got != "dex-c1" {
		t.Errorf("fullnameOverride = %v", got)
	}
	if got := dig(t, v, "configSecret", "create"); got != false {
		t.Errorf("configSecret.create = %v (must be false: ESO/Vault-synced Secret)", got)
	}
	if got := dig(t, v, "configSecret", "name"); got != DexConfigSecretName {
		t.Errorf("configSecret.name = %v", got)
	}
}

func TestArgoConfigOverlay(t *testing.T) {
	cfg := Config{ESOSecretStore: "vault-platform", ESOSecretStoreKind: "ClusterSecretStore"}
	groups := RBACGroups{
		Admin:  []string{"/tenant-acme/platform-team"},
		Viewer: []string{"/tenant-acme/viewers"},
	}
	raw, err := argoConfigOverlay(cfg, "cluster:abc-123", "prod-eu", groups)
	if err != nil {
		t.Fatal(err)
	}
	v := parseValues(t, raw)

	if got := dig(t, v, "argocd", "oidc", "issuerUrl"); got != "http://dex-abc-123.dex.svc.cluster.local:5556/dex" {
		t.Errorf("issuerUrl = %v", got)
	}
	if got := dig(t, v, "argocd", "oidc", "clientSecretRef", "name"); got != ArgoCDClientSecretName {
		t.Errorf("clientSecretRef.name = %v", got)
	}
	if got := dig(t, v, "argocd", "oidc", "clientSecretRef", "key"); got != ArgoCDClientSecretKey {
		t.Errorf("clientSecretRef.key = %v", got)
	}
	if got := dig(t, v, "argocd", "rbac", "policyDefault"); got != "" {
		t.Errorf("policyDefault = %q (must be empty/fail-closed)", got)
	}
	admins := dig(t, v, "argocd", "rbac", "adminGroups").([]any)
	if len(admins) != 1 || admins[0] != "/tenant-acme/platform-team" {
		t.Errorf("adminGroups = %v", admins)
	}
	viewers := dig(t, v, "argocd", "rbac", "viewerGroups").([]any)
	if len(viewers) != 1 || viewers[0] != "/tenant-acme/viewers" {
		t.Errorf("viewerGroups = %v", viewers)
	}
	// ESO wiring references the cluster's Vault path; no secret values.
	if got := dig(t, v, "argocd", "secrets", "secretStore"); got != "vault-platform" {
		t.Errorf("secrets.secretStore = %v", got)
	}
	if got := dig(t, v, "argocd", "secrets", "vaultPath"); got != "inari/clusters/abc-123/oidc-client-secret" {
		t.Errorf("secrets.vaultPath = %v", got)
	}
	if strings.Contains(string(raw), "client-secret-value") {
		t.Error("overlay must never embed secret material")
	}
}

func TestArgoConfigOverlayIssuerOverrideLabel(t *testing.T) {
	raw, err := argoConfigOverlay(Config{}, "c1", "prod-eu", RBACGroups{})
	if err != nil {
		t.Fatal(err)
	}
	v := parseValues(t, raw)
	if got := dig(t, v, "argocd", "oidc", "issuerUrl"); got != DefaultIssuerURL("c1") {
		t.Errorf("issuerUrl = %v", got)
	}
	// No secrets block when no ESO store is configured.
	if _, ok := dig(t, v, "argocd").(map[string]any)["secrets"]; ok {
		t.Error("secrets block must be omitted without a configured store")
	}
}

// --- RBAC group derivation from tenant teams ---

func TestRBACGroupsFromTeams(t *testing.T) {
	teams := []TeamRef{
		{RoleName: "viewer", GroupPath: "/tenant-acme/viewers"},
		{RoleName: "admin", GroupPath: "/tenant-acme/platform-team"},
		{RoleName: "editor", GroupPath: "/tenant-acme/devs"},
	}
	g, err := RBACGroupsFromTeams(teams)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Admin) != 1 || g.Admin[0] != "/tenant-acme/platform-team" {
		t.Errorf("admin = %v", g.Admin)
	}
	if len(g.Viewer) != 2 || g.Viewer[0] != "/tenant-acme/devs" || g.Viewer[1] != "/tenant-acme/viewers" {
		t.Errorf("viewer (sorted) = %v", g.Viewer)
	}
}

func TestRBACGroupsRejectNewlineInjection(t *testing.T) {
	_, err := RBACGroupsFromTeams([]TeamRef{
		{RoleName: "admin", GroupPath: "/tenant-acme/team\np, *, *, *, *, allow"},
	})
	if err == nil {
		t.Fatal("expected error: newline in group would inject RBAC policy lines")
	}
}

func TestRBACGroupsSkipsEmptyPath(t *testing.T) {
	g, err := RBACGroupsFromTeams([]TeamRef{{RoleName: "admin", GroupPath: ""}})
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Admin) != 0 {
		t.Errorf("admin = %v", g.Admin)
	}
}

// --- Dex config.yaml (Vault-bound; the only place secret material lives) ---

func TestRenderDexConfig(t *testing.T) {
	raw, err := RenderDexConfig(DexConfigInput{
		Issuer:             DefaultIssuerURL("c1"),
		KeycloakIssuerURL:  "https://keycloak.platform.example/realms/inari",
		ClientID:           "cluster-c1-dex",
		ClientSecret:       "kc-secret",
		ArgoCDStaticSecret: "static-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	v := parseValues(t, raw)

	if got := dig(t, v, "issuer"); got != "http://dex-c1.dex.svc.cluster.local:5556/dex" {
		t.Errorf("issuer = %v", got)
	}
	if got := dig(t, v, "web", "http"); got != "0.0.0.0:5556" {
		t.Errorf("web.http = %v", got)
	}
	if got := dig(t, v, "enablePasswordDB"); got != true {
		t.Errorf("enablePasswordDB = %v (break-glass parity)", got)
	}
	connectors := dig(t, v, "connectors").([]any)
	if len(connectors) != 1 {
		t.Fatalf("connectors = %v", connectors)
	}
	conn := connectors[0].(map[string]any)
	if conn["type"] != "oidc" || conn["id"] != "keycloak" {
		t.Errorf("connector = %+v", conn)
	}
	cc := conn["config"].(map[string]any)
	if cc["issuer"] != "https://keycloak.platform.example/realms/inari" {
		t.Errorf("connector issuer = %v", cc["issuer"])
	}
	if cc["clientID"] != "cluster-c1-dex" || cc["clientSecret"] != "kc-secret" {
		t.Errorf("connector client = %v", cc["clientID"])
	}
	if cc["redirectURI"] != "http://dex-c1.dex.svc.cluster.local:5556/dex/callback" {
		t.Errorf("redirectURI = %v", cc["redirectURI"])
	}
	if cc["getUserInfo"] != true {
		t.Errorf("getUserInfo = %v", cc["getUserInfo"])
	}
	scopes, _ := yaml.Marshal(cc["scopes"])
	for _, want := range []string{"openid", "profile", "email", "groups", "organization"} {
		if !strings.Contains(string(scopes), want) {
			t.Errorf("scopes missing %q: %s", want, scopes)
		}
	}
	clients := dig(t, v, "staticClients").([]any)
	if len(clients) != 1 {
		t.Fatalf("staticClients = %v", clients)
	}
	sc := clients[0].(map[string]any)
	if sc["id"] != "argocd" || sc["secret"] != "static-secret" {
		t.Errorf("staticClient = %+v", sc)
	}
}

// mustValuesYAML marshals a (values, err) pair; test helper (panics).
func mustValuesYAML(m map[string]any, err error) []byte {
	if err != nil {
		panic(err)
	}
	raw, err := yaml.Marshal(m)
	if err != nil {
		panic(err)
	}
	return raw
}
