package renderer

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func xpDesc(manifests string) types.SourceDescriptor {
	return types.SourceDescriptor{
		Kind:       types.SourceKindCrossplane,
		Crossplane: &types.XPSource{Manifests: json.RawMessage(manifests)},
	}
}

func xpParams() RenderParams {
	return RenderParams{
		Name: "acme", Namespace: "tenant-acme", ID: "tenant-acme-realm",
		DeployMode: types.AddonDeployModeApplication,
		RepoURL:    "https://github.com/acme/platform", BaseBranch: "main",
		Path:    "tenants/acme/keycloak/realm",
		Project: "tenant-acme",
	}
}

func TestXPHandlerClaimMultiDoc(t *testing.T) {
	r := New(nil)
	inline := `apiVersion: identity.inari.io/v1alpha1
kind: TenantRealm
metadata:
  name: acme
  namespace: tenant-acme
spec:
  tenantID: acme
  namespace: tenant-acme
---
apiVersion: identity.inari.io/v1alpha1
kind: TenantClient
metadata:
  name: acme-portal
  namespace: tenant-acme
spec:
  tenantID: acme
  namespace: tenant-acme
  realm: acme
`
	files, err := r.Render(context.Background(), xpDesc(mustJSONString(inline)), xpParams())
	if err != nil {
		t.Fatal(err)
	}
	byPath := filesByPath(files)
	if _, ok := byPath["tenants/acme/keycloak/realm/manifests/00-tenantrealm-acme.yaml"]; !ok {
		t.Errorf("missing realm claim: %v", byPath)
	}
	if _, ok := byPath["tenants/acme/keycloak/realm/manifests/01-tenantclient-acme-portal.yaml"]; !ok {
		t.Errorf("missing client claim: %v", byPath)
	}
	app := parseDoc(t, byPath["tenants/acme/keycloak/realm/application.yaml"])
	spec := app["spec"].(map[string]any)
	if spec["project"] != "tenant-acme" {
		t.Errorf("project = %v", spec["project"])
	}
	src := spec["source"].(map[string]any)
	if src["path"] != "tenants/acme/keycloak/realm/manifests" {
		t.Errorf("application should source the manifests dir: %v", src)
	}
	dest := spec["destination"].(map[string]any)
	if dest["namespace"] != "tenant-acme" {
		t.Errorf("destination = %v", dest)
	}
}

func TestXPHandlerValidation(t *testing.T) {
	r := New(nil)
	p := xpParams()

	// Missing payload is rejected by descriptor validation.
	if _, err := r.Render(context.Background(), types.SourceDescriptor{Kind: types.SourceKindCrossplane}, p); err == nil {
		t.Error("missing payload: expected error")
	}
	// Empty manifests are rejected.
	if _, err := r.Render(context.Background(), xpDesc(`""`), p); err == nil {
		t.Error("empty manifests: expected error")
	}
	// Documents still go through kind/name validation.
	bad := mustJSONString("apiVersion: identity.inari.io/v1alpha1\nkind: TenantRealm\n")
	if _, err := r.Render(context.Background(), xpDesc(bad), p); err == nil ||
		!strings.Contains(err.Error(), "metadata.name") {
		t.Errorf("nameless claim: err = %v", err)
	}
}

func TestXPHandlerApplicationSet(t *testing.T) {
	r := New(nil)
	p := xpParams()
	p.DeployMode = types.AddonDeployModeApplicationSet
	p.AppPrefix = PrefixAddonSet
	p.Clusters = []ClusterTarget{{ID: "c1", Name: "hub"}}
	inline := mustJSONString("apiVersion: identity.inari.io/v1alpha1\nkind: TenantRealm\nmetadata:\n  name: acme\n")
	files, err := r.Render(context.Background(), xpDesc(inline), p)
	if err != nil {
		t.Fatal(err)
	}
	doc := parseDoc(t, filesByPath(files)[p.Path+"/applicationset.yaml"])
	tpl := doc["spec"].(map[string]any)["template"].(map[string]any)
	if tpl["spec"].(map[string]any)["source"].(map[string]any)["path"] != p.Path+"/manifests" {
		t.Errorf("appset template source = %v", tpl["spec"])
	}
}
