package platformresources

import (
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestPlatformResourceKindValid(t *testing.T) {
	valid := []types.PlatformResourceKind{
		types.PlatformKindKeycloakRealm,
		types.PlatformKindKeycloakClient,
		types.PlatformKindDNSZone,
		types.PlatformKindTenantNamespace,
	}
	for _, k := range valid {
		if !k.Valid() {
			t.Errorf("PlatformResourceKind(%q).Valid() = false, want true", k)
		}
	}
	for _, k := range []types.PlatformResourceKind{"", "cluster", "KEYCLOAK-REALM"} {
		if k.Valid() {
			t.Errorf("PlatformResourceKind(%q).Valid() = true, want false", k)
		}
	}
}

func TestPlatformResourceStatusValid(t *testing.T) {
	valid := []types.PlatformResourceStatus{
		types.PlatformStatusReady,
		types.PlatformStatusReconciling,
		types.PlatformStatusFailed,
	}
	for _, s := range valid {
		if !s.Valid() {
			t.Errorf("PlatformResourceStatus(%q).Valid() = false, want true", s)
		}
	}
	for _, s := range []types.PlatformResourceStatus{"", "pending", "READY"} {
		if s.Valid() {
			t.Errorf("PlatformResourceStatus(%q).Valid() = true, want false", s)
		}
	}
}
