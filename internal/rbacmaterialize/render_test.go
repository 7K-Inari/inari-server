package rbacmaterialize

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

func testTeams() []types.Team {
	return []types.Team{
		{ID: "team:2", OrgID: "org:1", Name: "platform-team", Role: types.RolePlatformEngineer, KeycloakGroupPath: "tenant-acme/platform-team"},
		{ID: "team:1", OrgID: "org:1", Name: "admins", Role: types.RoleOrgAdmin, KeycloakGroupPath: "tenant-acme/admins"},
		{ID: "team:3", OrgID: "org:1", Name: "devs", Role: types.RoleDeveloper, KeycloakGroupPath: "tenant-acme/devs"},
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
	files := RenderTenantRBAC("acme", testTeams())
	content := fileByPath(t, files, "baseline/rbac/clusterroles.yaml")
	docs := yamlDocs(t, content)
	if len(docs) != 4 {
		t.Fatalf("expected 4 anchor ClusterRoles, got %d", len(docs))
	}
	want := []string{"tenant-acme-admin", "tenant-acme-operator", "tenant-acme-editor", "tenant-acme-viewer"}
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
	files := RenderTenantRBAC("acme", nil)
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
	files := RenderTenantRBAC("acme", nil)
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

func TestRenderTenantRBACBindings(t *testing.T) {
	files := RenderTenantRBAC("acme", testTeams())
	docs := yamlDocs(t, fileByPath(t, files, "baseline/rbac/clusterrolebindings.yaml"))
	if len(docs) != 3 {
		t.Fatalf("expected 3 bindings, got %d", len(docs))
	}
	// Deterministic order: bindings sorted by team name (admins, devs, platform-team).
	type want struct {
		name, role, group string
	}
	wants := []want{
		{"tenant-acme-admins", "tenant-acme-admin", "/tenant-acme/admins"},
		{"tenant-acme-devs", "tenant-acme-editor", "/tenant-acme/devs"},
		{"tenant-acme-platform-team", "tenant-acme-operator", "/tenant-acme/platform-team"},
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

func TestRenderTenantRBACDeterministic(t *testing.T) {
	a := RenderTenantRBAC("acme", testTeams())
	b := RenderTenantRBAC("acme", testTeams())
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
	files := RenderTenantRBAC("acme", nil)
	if docs := yamlDocs(t, fileByPath(t, files, "baseline/rbac/clusterroles.yaml")); len(docs) != 4 {
		t.Errorf("empty teams: expected 4 anchor roles, got %d", len(docs))
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
