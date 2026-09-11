// Tenant bootstrap (M7.W2): the base platform-resource rows every tenant
// gets (keycloak-realm, dns-zone, tenant-namespace) and the GitOps CR
// manifests (inari-operator api/v1alpha1) rendered for the platform GitOps
// repo. Desired state only — the reconciler + status sink are a later task.
package platformresources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// resourceSpec is one desired-state row to upsert for a tenant.
type resourceSpec struct {
	orgID   string
	kind    types.PlatformResourceKind
	name    string
	desired json.RawMessage
}

// baseResourceSpecs are the platform resources every tenant gets:
// the Keycloak realm organization, the tenant's DNSRecord set under the
// shared platform zone, and the tenant namespace on the hub cluster.
func baseResourceSpecs(org *types.Organization) []resourceSpec {
	return []resourceSpec{
		{
			orgID:   org.ID,
			kind:    types.PlatformKindKeycloakRealm,
			name:    org.Slug,
			desired: json.RawMessage(fmt.Sprintf(`{"realm":"inari","organization":%q}`, org.Slug)),
		},
		{
			orgID:   org.ID,
			kind:    types.PlatformKindDNSZone,
			name:    org.Slug,
			desired: json.RawMessage(`{"mode":"shared-record"}`),
		},
		{
			orgID:   org.ID,
			kind:    types.PlatformKindTenantNamespace,
			name:    "tenant-" + org.Slug,
			desired: json.RawMessage(fmt.Sprintf(`{"namespace":%q}`, "tenant-"+org.Slug)),
		},
	}
}

// EnsureBaseResources idempotently upserts the base platform-resource rows
// for a tenant. Reused by the CreateTenant hook, the tenant-zone wiring, and
// the startup backfill; repeat calls are side-effect free (EnsureDesired
// only audits when the row is new or the desired state changed).
func (s *Service) EnsureBaseResources(ctx context.Context, org *types.Organization) error {
	for _, spec := range baseResourceSpecs(org) {
		if _, err := s.EnsureDesired(ctx, spec.orgID, spec.kind, spec.name, spec.desired); err != nil {
			return fmt.Errorf("platformresources: ensure %s %s: %w", spec.kind, spec.name, err)
		}
	}
	return nil
}

// RenderTenantManifests renders the tenant CR manifests (inari-operator
// api/v1alpha1) for the platform GitOps repo. Layout: one directory per
// tenant at tenants/<slug>/, synced by a single ArgoCD ApplicationSet with a
// git-directories generator (see docs/platform-gitops.md). Filenames are
// stable so repeat commits are no-ops when nothing changed.
func RenderTenantManifests(org *types.Organization) []gitprovider.File {
	realm := fmt.Sprintf(`apiVersion: inari.7k.io/v1alpha1
kind: KeycloakRealm
metadata:
  name: %s
  labels:
    inari.7k.io/org: %s
spec:
  realm: inari
  organization: %s
`, org.Slug, org.ID, org.Slug)
	dns := fmt.Sprintf(`apiVersion: inari.7k.io/v1alpha1
kind: DNSRecord
metadata:
  name: %s
  labels:
    inari.7k.io/org: %s
spec:
  mode: shared-record
  recordPrefix: tenant-%s
`, org.Slug, org.ID, org.Slug)
	ns := fmt.Sprintf(`apiVersion: inari.7k.io/v1alpha1
kind: TenantNamespace
metadata:
  name: tenant-%s
  labels:
    inari.7k.io/org: %s
spec:
  namespace: tenant-%s
`, org.Slug, org.ID, org.Slug)
	return []gitprovider.File{
		{Path: "tenants/" + org.Slug + "/keycloak-realm.yaml", Content: []byte(realm)},
		{Path: "tenants/" + org.Slug + "/dns-record.yaml", Content: []byte(dns)},
		{Path: "tenants/" + org.Slug + "/tenant-namespace.yaml", Content: []byte(ns)},
	}
}
