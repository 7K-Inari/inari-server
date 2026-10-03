package authz

import (
	"slices"
	"testing"
)

func TestPermissionCatalog(t *testing.T) {
	cat := PermissionCatalog()
	if len(cat) != 20 {
		t.Fatalf("catalog size = %d, want 20", len(cat))
	}
	seen := map[string]bool{}
	for _, p := range cat {
		if p.Slug == "" || p.Name == "" || p.Domain == "" {
			t.Fatalf("incomplete catalog entry: %+v", p)
		}
		if seen[p.Slug] {
			t.Fatalf("duplicate slug %q", p.Slug)
		}
		seen[p.Slug] = true
		if !ValidPermission(p.Slug) {
			t.Fatalf("catalog slug %q fails ValidPermission", p.Slug)
		}
	}
	if ValidPermission("tenant.nonexistent") {
		t.Fatal("unknown slug must not validate")
	}
}

func TestPermissionRelation(t *testing.T) {
	rel, ok := PermissionRelation(PermTenantSettingsWrite)
	if !ok || rel != "tenant_settings_write" {
		t.Fatalf("PermissionRelation(tenant.settings.write) = %q, %v", rel, ok)
	}
	if _, ok := PermissionRelation("bogus"); ok {
		t.Fatal("unknown slug must not map to a relation")
	}
	// Every catalog slug maps to a distinct FGA relation (relations cannot
	// contain '.'; the underscore mapping must stay collision-free).
	rels := map[string]string{}
	for _, p := range PermissionCatalog() {
		rel, ok := PermissionRelation(p.Slug)
		if !ok {
			t.Fatalf("catalog slug %q has no relation", p.Slug)
		}
		if prev, dup := rels[rel]; dup {
			t.Fatalf("slugs %q and %q collide on relation %q", prev, p.Slug, rel)
		}
		rels[rel] = p.Slug
	}
}

func TestBuiltinRoles(t *testing.T) {
	roles := BuiltinRoles()
	if len(roles) != 4 {
		t.Fatalf("BuiltinRoles len = %d, want 4", len(roles))
	}
	byName := map[string]BuiltinRole{}
	for _, r := range roles {
		byName[r.Name] = r
		for _, p := range r.Permissions {
			if !ValidPermission(p) {
				t.Fatalf("builtin %q grants unknown permission %q", r.Name, p)
			}
		}
	}
	admin := byName["admin"]
	if len(admin.Permissions) != len(PermissionCatalog()) {
		t.Fatalf("admin bundle = %d permissions, want the full catalog", len(admin.Permissions))
	}
	operator := byName["operator"]
	for _, excluded := range []string{
		PermTenantAdmin, PermTenantSettingsWrite, PermTenantTeamsManage,
		PermTenantRBACManage, PermTenantIdentityManage, PermTenantNotificationsManage,
	} {
		if slices.Contains(operator.Permissions, excluded) {
			t.Fatalf("operator bundle must not contain %q", excluded)
		}
	}
	if got := byName["editor"].Permissions; !slices.Contains(got, PermDeploymentsCreate) || slices.Contains(got, PermClustersRegister) {
		t.Fatalf("editor bundle wrong: %v", got)
	}
	if got := byName["viewer"].Permissions; len(got) != 1 || got[0] != PermTenantRead {
		t.Fatalf("viewer bundle = %v, want [tenant.read]", got)
	}
	// Hierarchy preservation: admin ⊇ operator ⊇ editor ⊇ viewer.
	subset := func(child, parent BuiltinRole) bool {
		for _, p := range child.Permissions {
			if !slices.Contains(parent.Permissions, p) {
				return false
			}
		}
		return true
	}
	if !subset(byName["viewer"], byName["editor"]) || !subset(byName["editor"], operator) || !subset(operator, admin) {
		t.Fatal("builtin bundles must preserve the retired role hierarchy")
	}
}

func TestK8sFragmentTier(t *testing.T) {
	cases := map[string]string{
		PermTenantRead:          "viewer",
		PermTenantAdmin:         "admin",
		PermClustersRegister:    "operator",
		PermCatalogManage:       "editor",
		PermDeploymentsCreate:   "editor",
		PermTenantMembersManage: "",
		PermApprovalsManage:     "",
		PermExtensionsInvoke:    "",
	}
	for slug, want := range cases {
		if got := K8sFragmentTier(slug); got != want {
			t.Fatalf("K8sFragmentTier(%q) = %q, want %q", slug, got, want)
		}
	}
	if got := K8sFragmentTier("bogus"); got != "" {
		t.Fatalf("unknown slug tier = %q, want empty", got)
	}
}
