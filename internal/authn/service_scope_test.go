package authn

import "testing"

func TestIdentityProvisioningScope(t *testing.T) {
	identity := &Identity{Scopes: ParseScopes("openid provisioning write")}
	if len(identity.Scopes) != 3 || !identity.HasScope("provisioning") || !identity.HasScope("openid") {
		t.Fatalf("scopes not parsed: %#v", identity.Scopes)
	}
	if identity.HasScope("admin") || identity.HasScope("") {
		t.Fatal("unexpected scope grant")
	}
}
