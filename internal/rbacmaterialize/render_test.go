package rbacmaterialize

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// testRoles returns the four seeded built-ins (ADR-0013 bundles).
func testRoles() []types.Role {
	var out []types.Role
	for _, b := range authz.BuiltinRoles() {
		out = append(out, types.Role{
			ID: "r-" + b.Name, OrgID: "org:1", Name: b.Name,
			DisplayName: b.DisplayName, Builtin: true, Permissions: b.Permissions,
		})
	}
	return out
}

func testTeams() []types.Team {
	return []types.Team{
		{ID: "team:2", OrgID: "org:1", Name: "platform-team", RoleID: "r-operator", RoleName: "operator", KeycloakGroupPath: "tenant-acme/platform-team"},
		{ID: "team:1", OrgID: "org:1", Name: "admins", RoleID: "r-admin", RoleName: "admin", KeycloakGroupPath: "tenant-acme/admins"},
		{ID: "team:3", OrgID: "org:1", Name: "devs", RoleID: "r-editor", RoleName: "editor", KeycloakGroupPath: "tenant-acme/devs"},
	}
}

func fileByPath(t *testing.T, files []gitprovider.File, path string) string {
	t.Helper()
	for _, f := range files {
		if f.Path == path {
			return string(f.Content)
		}
	}
	t.Fatalf("file %q not rendered (have %v)", path, files)
	return ""
}

func yamlDocs(t *testing.T, content string) []map[string]any {
	t.Helper()
	var docs []map[string]any
	dec := yaml.NewDecoder(strings.NewReader(content))
	for {
		var doc map[string]any
		err := dec.Decode(&doc)
		if err != nil {
			break
		}
		docs = append(docs, doc)
	}
	return docs
}

func TestRenderTenantRBACClusterRoles(t *testing.T) {
	files := RenderTenantRBAC("acme", testRoles(), testTeams())
	content := fileByPath(t, files, "baseline/rbac/clusterroles.yaml")
	docs := yamlDocs(t, content)
	if len(docs) != 4 {
		t.Fatalf("expected 4 ClusterRoles (one per org role), got %d", len(docs))
	}
	// Deterministic document order by role name.
	want := []string{"tenant-acme-admin", "tenant-acme-editor", "tenant-acme-operator", "tenant-acme-viewer"}
	for i, name := range want {
		if docs[i]["kind"] != "ClusterRole" {
			t.Errorf("doc %d kind = %v", i, docs[i]["kind"])
		}
		meta, _ := docs[i]["metadata"].(map[string]any)
		if meta["name"] != name {
			t.Errorf("doc %d name = %v, want %s", i, meta["name"], name)
		}
		labels, _ := meta["labels"].(map[string]any)
		if labels["app.kubernetes.io/managed-by"] != "inari" {
			t.Errorf("doc %d missing managed-by label", i)
		}
		if labels["inari.io/tenant"] != "acme" {
			t.Errorf("doc %d missing tenant label", i)
		}
	}
}

func TestRenderTenantRBACAdminIsClusterAdminEquivalent(t *testing.T) {
	files := RenderTenantRBAC("acme", testRoles(), nil)
	docs := yamlDocs(t, fileByPath(t, files, "baseline/rbac/clusterroles.yaml"))
	rules, _ := docs[0]["rules"].([]any)
	if len(rules) == 0 {
		t.Fatal("admin role has no rules")
	}
	rule, _ := rules[0].(map[string]any)
	groups, _ := rule["apiGroups"].([]any)
	if len(groups) == 0 || groups[0] != "*" {
		t.Errorf("admin rule apiGroups = %v, want [*]", rule["apiGroups"])
	}
	verbs, _ := rule["verbs"].([]any)
	if len(verbs) == 0 || verbs[0] != "*" {
		t.Errorf("admin rule verbs = %v, want [*]", rule["verbs"])
	}
}

func TestRenderTenantRBACViewerIsReadOnly(t *testing.T) {
	files := RenderTenantRBAC("acme", testRoles(), nil)
	docs := yamlDocs(t, fileByPath(t, files, "baseline/rbac/clusterroles.yaml"))
	rules, _ := docs[3]["rules"].([]any)
	for _, r := range rules {
		rule, _ := r.(map[string]any)
		for _, v := range rule["verbs"].([]any) {
			verb, _ := v.(string)
			if verb != "get" && verb != "list" && verb != "watch" {
				t.Errorf("viewer role grants mutating verb %q", verb)
			}
		}
	}
}

// TestRenderTenantRBACCustomRole pins the role-engine render (ADR-0013): a
// custom role gets its own ClusterRole whose rules are the union fragment
// of its permissions' k8s tiers; a tenant-plane-only role renders an empty
// rules list.
func TestRenderTenantRBACCustomRole(t *testing.T) {
	roles := append(testRoles(),
		types.Role{ID: "r-deployer", OrgID: "org:1", Name: "deployer", Permissions: []string{"deployments.create", "catalog.manage"}},
		types.Role{ID: "r-people", OrgID: "org:1", Name: "people-ops", Permissions: []string{"tenant.members.manage"}},
	)
	teams := append(testTeams(),
		types.Team{ID: "team:4", OrgID: "org:1", Name: "release", RoleID: "r-deployer", RoleName: "deployer", KeycloakGroupPath: "tenant-acme/release"},
	)
	files := RenderTenantRBAC("acme", roles, teams)
	content := fileByPath(t, files, "baseline/rbac/clusterroles.yaml")
	docs := yamlDocs(t, content)
	if len(docs) != 6 {
		t.Fatalf("expected 6 ClusterRoles, got %d", len(docs))
	}
	// deployer (editor fragment) renders CRUD rules; people-ops renders none.
	deployer := docs[1] // admin, deployer, editor, operator, people-ops, viewer
	meta, _ := deployer["metadata"].(map[string]any)
	if meta["name"] != "tenant-acme-deployer" {
		t.Fatalf("doc 1 = %v, want tenant-acme-deployer", meta["name"])
	}
	rules, _ := deployer["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("deployer rules = %v, want the editor fragment", rules)
	}
	rule, _ := rules[0].(map[string]any)
	verbs, _ := rule["verbs"].([]any)
	if len(verbs) != 7 {
		t.Errorf("deployer verbs = %v, want editor CRUD", verbs)
	}
	people := docs[4]
	pmeta, _ := people["metadata"].(map[string]any)
	if pmeta["name"] != "tenant-acme-people-ops" {
		t.Fatalf("doc 4 = %v, want tenant-acme-people-ops", pmeta["name"])
	}
	prules, _ := people["rules"].([]any)
	if len(prules) != 0 {
		t.Errorf("tenant-plane-only role must render empty rules, got %v", prules)
	}
	// Binding for the custom role is role-qualified.
	bindings := fileByPath(t, files, "baseline/rbac/clusterrolebindings.yaml")
	if !strings.Contains(bindings, "name: tenant-acme-release-deployer") {
		t.Errorf("custom-role binding missing:\n%s", bindings)
	}
}

func TestRenderTenantRBACBindings(t *testing.T) {
	files := RenderTenantRBAC("acme", testRoles(), testTeams())
	docs := yamlDocs(t, fileByPath(t, files, "baseline/rbac/clusterrolebindings.yaml"))
	if len(docs) != 3 {
		t.Fatalf("expected 3 bindings, got %d", len(docs))
	}
	// Deterministic order: bindings sorted by team name (admins, devs, platform-team).
	type want struct {
		name, role, group string
	}
	wants := []want{
		{"tenant-acme-admins-admin", "tenant-acme-admin", "/tenant-acme/admins"},
		{"tenant-acme-devs-editor", "tenant-acme-editor", "/tenant-acme/devs"},
		{"tenant-acme-platform-team-operator", "tenant-acme-operator", "/tenant-acme/platform-team"},
	}
	for i, w := range wants {
		meta, _ := docs[i]["metadata"].(map[string]any)
		if meta["name"] != w.name {
			t.Errorf("binding %d name = %v, want %s", i, meta["name"], w.name)
		}
		ref, _ := docs[i]["roleRef"].(map[string]any)
		if ref["kind"] != "ClusterRole" || ref["name"] != w.role {
			t.Errorf("binding %d roleRef = %v, want ClusterRole/%s", i, ref, w.role)
		}
		subjects, _ := docs[i]["subjects"].([]any)
		if len(subjects) != 1 {
			t.Fatalf("binding %d subjects = %v, want exactly one", i, subjects)
		}
		sub, _ := subjects[0].(map[string]any)
		if sub["kind"] != "Group" || sub["name"] != w.group {
			t.Errorf("binding %d subject = %v, want Group/%s", i, sub, w.group)
		}
	}
}

// A role flip must render a NEW binding object, never an in-place roleRef
// change: ClusterRoleBinding roleRef is immutable, so the syncer (ArgoCD)
// applies the new binding and prunes the stale one (QA: k3s rejects
// in-place flips with "cannot change roleRef").
func TestRenderTenantRBACRoleFlipRendersNewBinding(t *testing.T) {
	teams := testTeams()
	before := RenderTenantRBAC("acme", testRoles(), teams)
	devsBefore := "tenant-acme-devs-editor"
	if !strings.Contains(fileByPath(t, before, "baseline/rbac/clusterrolebindings.yaml"), "name: "+devsBefore) {
		t.Fatalf("expected binding %s before the flip", devsBefore)
	}
	for i := range teams {
		if teams[i].Name == "devs" {
			teams[i].RoleName = "viewer"
		}
	}
	after := fileByPath(t, RenderTenantRBAC("acme", testRoles(), teams), "baseline/rbac/clusterrolebindings.yaml")
	if !strings.Contains(after, "name: tenant-acme-devs-viewer") {
		t.Errorf("flipped binding missing new role-qualified name:\n%s", after)
	}
	if strings.Contains(after, "name: "+devsBefore) {
		t.Errorf("stale binding %s still rendered after the flip:\n%s", devsBefore, after)
	}
}

func TestRenderTenantRBACDeterministic(t *testing.T) {
	a := RenderTenantRBAC("acme", testRoles(), testTeams())
	b := RenderTenantRBAC("acme", testRoles(), testTeams())
	if len(a) != len(b) {
		t.Fatalf("file count differs: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Path != b[i].Path || string(a[i].Content) != string(b[i].Content) {
			t.Errorf("render not deterministic at %q", a[i].Path)
		}
	}
}

func TestRenderTenantRBACNoTeams(t *testing.T) {
	files := RenderTenantRBAC("acme", testRoles(), nil)
	if docs := yamlDocs(t, fileByPath(t, files, "baseline/rbac/clusterroles.yaml")); len(docs) != 4 {
		t.Errorf("empty teams: expected 4 role ClusterRoles, got %d", len(docs))
	}
	if docs := yamlDocs(t, fileByPath(t, files, "baseline/rbac/clusterrolebindings.yaml")); len(docs) != 0 {
		t.Errorf("empty teams: expected no bindings, got %d", len(docs))
	}
}

func TestGroupSubjectName(t *testing.T) {
	// Keycloak's group-membership mapper emits full paths with a leading
	// slash; the ClusterRoleBinding Group subject must match the claim.
	if got := GroupSubjectName("tenant-acme/admins"); got != "/tenant-acme/admins" {
		t.Errorf("GroupSubjectName = %q", got)
	}
	if got := GroupSubjectName("/tenant-acme/admins"); got != "/tenant-acme/admins" {
		t.Errorf("GroupSubjectName idempotent = %q", got)
	}
}
