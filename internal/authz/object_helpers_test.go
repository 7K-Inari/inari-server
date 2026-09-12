package authz

import (
	"errors"
	"strings"
	"testing"
)

// The object id part of an OpenFGA object string (after "type:") may not
// contain ':' or '#'. These tests pin the mapping for IDs that persist with
// a "<type>:" marker prefix (plan §5.2) — regression coverage for the
// live incident where tuples were written as "cluster:cluster:<uuid>" and
// rejected by OpenFGA validation.
func TestObjectHelpersStripStoredTypePrefixes(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"org prefixed", OrgObject("org:abc-123"), "organization:abc-123"},
		{"org bare", OrgObject("abc-123"), "organization:abc-123"},
		{"cluster prefixed", ClusterObject("cluster:abc-123"), "cluster:abc-123"},
		{"cluster bare", ClusterObject("abc-123"), "cluster:abc-123"},
		{"extension prefixed", ExtensionObject("extension:abc-123"), "extension:abc-123"},
		{"zone prefixed", TenantZoneObject("zone:abc-123"), "tenant_zone:abc-123"},
		{"clusterset prefixed", ClusterSetObject("clusterset:abc-123"), "cluster_set:abc-123"},
		{"policypack prefixed", PolicyPackObject("policypack:abc-123"), "policy_pack:abc-123"},
		{"cloudaccount prefixed", CloudAccountObject("cloudaccount:abc-123"), "cloud_account:abc-123"},
		{"rollout prefixed", RolloutObject("rollout:abc-123"), "rollout:abc-123"},
		{"drift prefixed", DriftEventObject("drift:abc-123"), "drift_event:abc-123"},
		{"catalog platform item", CatalogItemObject("platform:keycloak"), "catalog_item:platform/keycloak"},
		{"catalog discovered item", CatalogItemObject("discovered:cluster-1:Pod/web"), "catalog_item:discovered/cluster-1/Pod/web"},
		{"instance bare", ResourceInstanceObject("web-a1b2c3d4"), "resource_instance:web-a1b2c3d4"},
		{"team uuid", TeamObject("9f1b2c3d-0000-4000-8000-000000000000"), "team:9f1b2c3d-0000-4000-8000-000000000000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("got %q want %q", tc.got, tc.want)
			}
			// Exactly one ':' — the type separator.
			if strings.Count(tc.got, ":") != 1 {
				t.Fatalf("object string %q contains %d ':' separators, want exactly 1", tc.got, strings.Count(tc.got, ":"))
			}
			if strings.Contains(tc.got, "#") || strings.Contains(tc.got, "@") {
				t.Fatalf("object string %q contains a forbidden character", tc.got)
			}
		})
	}
}

func TestStripTypePrefixStripsExactlyOnePrefix(t *testing.T) {
	if got := stripTypePrefix("cluster:cluster:x", "cluster"); got != "cluster:x" {
		t.Fatalf("got %q", got)
	}
	if got := stripTypePrefix("plain", "cluster"); got != "plain" {
		t.Fatalf("unprefixed id changed: %q", got)
	}
}

func TestTupleErrorClassifiers(t *testing.T) {
	exists := errors.New(`authz: write tuples: POST validation error: {"code":"write_failed_due_to_invalid_input","message":"cannot write a tuple which already exists"}`)
	if !isTupleExistsErr(exists) || isTupleMissingErr(exists) {
		t.Fatal("already-exists error misclassified")
	}
	missing := errors.New(`authz: delete tuples: POST validation error: {"code":"write_failed_due_to_invalid_input","message":"cannot delete a tuple which does not exist"}`)
	if !isTupleMissingErr(missing) || isTupleExistsErr(missing) {
		t.Fatal("does-not-exist error misclassified")
	}
	other := errors.New("connection refused")
	if isTupleExistsErr(other) || isTupleMissingErr(other) {
		t.Fatal("unrelated error must not be classified as idempotent")
	}
}
