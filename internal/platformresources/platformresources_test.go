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

func TestIsPlatformKind(t *testing.T) {
	for _, kind := range []string{
		"TenantRealm.identity.inari.io",
		"DNSEndpoint.externaldns.k8s.io",
	} {
		if !IsPlatformKind(kind) {
			t.Errorf("IsPlatformKind(%q) = false, want true", kind)
		}
	}
	// Legacy platform.inari.io CRDs are gone (D7) and must not route.
	for _, kind := range []string{"", "Deployment", "apps/Deployment", "platform.inari.io",
		"KeycloakRealm.platform.inari.io", "DNSRecord.platform.inari.io"} {
		if IsPlatformKind(kind) {
			t.Errorf("IsPlatformKind(%q) = true, want false", kind)
		}
	}
}

func TestKindForCRD(t *testing.T) {
	cases := map[string]types.PlatformResourceKind{
		"TenantRealm.identity.inari.io":   types.PlatformKindKeycloakRealm,
		"TenantClient.identity.inari.io":  types.PlatformKindKeycloakClient,
		"DNSEndpoint.externaldns.k8s.io":  types.PlatformKindDNSZone,
		"TenantNamespace.stacks.inari.io": types.PlatformKindTenantNamespace,
	}
	for crd, want := range cases {
		got, ok := KindForCRD(crd)
		if !ok || got != want {
			t.Errorf("KindForCRD(%q) = %q,%v, want %q,true", crd, got, ok, want)
		}
	}
	for _, crd := range []string{"", "Deployment", "Unknown.platform.inari.io",
		"KeycloakRealm.platform.inari.io", "DNSRecord.platform.inari.io"} {
		if got, ok := KindForCRD(crd); ok {
			t.Errorf("KindForCRD(%q) = %q,true, want false", crd, got)
		}
	}
}

func TestDeriveStatus(t *testing.T) {
	cases := map[string]types.PlatformResourceStatus{
		"healthy":     types.PlatformStatusReady,
		"progressing": types.PlatformStatusReconciling,
		"degraded":    types.PlatformStatusFailed,
		"unknown":     types.PlatformStatusReconciling,
		"":            types.PlatformStatusReconciling,
	}
	for health, want := range cases {
		if got := deriveStatus(health); got != want {
			t.Errorf("deriveStatus(%q) = %q, want %q", health, got, want)
		}
	}
}
