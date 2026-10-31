// Tenant bootstrap (M7.W2): the base platform-resource rows every tenant
// gets (keycloak-realm, dns-zone, tenant-namespace). Desired state only —
// the rendered manifests live in render.go (renderer source descriptors,
// committed to the hub-facing platform repo).
package platformresources

import (
	"context"
	"encoding/json"
	"fmt"

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
