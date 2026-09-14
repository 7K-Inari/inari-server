// Package rbacmaterialize closes the RBAC-mapping chain (plan §7.1): it
// renders the four per-tenant anchor ClusterRoles
// (tenant-<slug>-admin/operator/editor/viewer) plus one role-qualified
// ClusterRoleBinding per team mapping (tenant-<slug>-<team>-<role>;
// role-qualified because roleRef is immutable — a mapping flip must create
// a new object and prune the old one, never update in place) as desired
// state into the tenant's <slug>-inari-state repo under baseline/rbac/ —
// the tenant-local ArgoCD root app syncs only baseline/, so committing
// there is sufficient for convergence (same constraint as
// secretstores.stateRepoPath). Role names are pinned to the RBAC matrix
// API contract (tenancy identity_http.go synthesizes the same names).
package rbacmaterialize

import (
	"fmt"
	"sort"
	"strings"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// State repo paths (must stay under baseline/ — see package doc).
const (
	ClusterRolesPath        = "baseline/rbac/clusterroles.yaml"
	ClusterRoleBindingsPath = "baseline/rbac/clusterrolebindings.yaml"
	RootAppPath             = "baseline/argocd/root-app.yaml"
)

// anchorRoles maps each org role onto its anchor ClusterRole suffix. The
// names (tenant-<slug>-<suffix>) are the RBAC matrix API contract — do not
// change without changing tenancy's getRBACMatrix.
var anchorRoles = []struct {
	Suffix string
	Role   types.Role
	Rules  string
}{
	// admin: full tenant administration — cluster-admin equivalent (the
	// tenant cluster is dedicated to the tenant).
	{"admin", types.RoleOrgAdmin, `
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
  - nonResourceURLs: ["*"]
    verbs: ["*"]`},
	// operator: edit workload resources + operate the tenant's GitOps and
	// infrastructure CRs (ArgoCD apps, Crossplane claims, kro instances).
	{"operator", types.RolePlatformEngineer, `
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["argoproj.io"]
    resources: ["applications", "applicationsets", "appprojects"]
    verbs: ["*"]
  - apiGroups: ["apiextensions.crossplane.io", "pkg.crossplane.io", "kro.run"]
    resources: ["*"]
    verbs: ["*"]`},
	// editor: deploy and edit resources.
	{"editor", types.RoleDeveloper, `
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]`},
	// viewer: read-only.
	{"viewer", types.RoleViewer, `
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["get", "list", "watch"]`},
}

// anchorSuffix maps an org role onto its anchor role suffix; ok is false
// for unknown roles (callers skip such teams rather than rendering a
// binding to a role that does not exist).
func anchorSuffix(role types.Role) (string, bool) {
	for _, a := range anchorRoles {
		if a.Role == role {
			return a.Suffix, true
		}
	}
	return "", false
}

// ClusterRoleName returns the anchor ClusterRole for an org role.
func ClusterRoleName(slug string, role types.Role) (string, bool) {
	suffix, ok := anchorSuffix(role)
	if !ok {
		return "", false
	}
	return "tenant-" + slug + "-" + suffix, true
}

// BindingName returns the ClusterRoleBinding for a team mapping. The name
// is role-qualified (tenant-<slug>-<team>-<role>) because roleRef is
// immutable: a mapping change must produce a NEW binding object (the
// ArgoCD root app prunes the stale one) instead of an in-place update the
// API server rejects.
func BindingName(slug, team string, role types.Role) (string, bool) {
	suffix, ok := anchorSuffix(role)
	if !ok {
		return "", false
	}
	return "tenant-" + slug + "-" + team + "-" + suffix, true
}

// GroupSubjectName maps a stored Keycloak group path
// (tenant-<slug>/<team>) onto the Group subject name used in bindings.
// Keycloak's group-membership protocol mapper emits full group paths with
// a leading slash in token claims, and the subject must match the claim
// exactly. Keep this the single place that knows the format.
func GroupSubjectName(groupPath string) string {
	if strings.HasPrefix(groupPath, "/") {
		return groupPath
	}
	return "/" + groupPath
}

// RenderTenantRBAC produces the tenant's RBAC desired-state files:
// baseline/rbac/clusterroles.yaml (always the four anchor roles) and
// baseline/rbac/clusterrolebindings.yaml (one role-qualified binding per
// team, sorted by team name so an unchanged desired state produces no git
// diff; a role change renders a new binding name and the ArgoCD root app
// prunes the stale one — roleRef is immutable, so in-place flips are
// rejected by the API server).
func RenderTenantRBAC(slug string, teams []types.Team) []gitprovider.File {
	var roles strings.Builder
	for i, a := range anchorRoles {
		if i > 0 {
			roles.WriteString("---\n")
		}
		fmt.Fprintf(&roles, `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: tenant-%s-%s
  labels:
    app.kubernetes.io/managed-by: inari
    inari.io/tenant: %s
rules:%s
`, slug, a.Suffix, slug, a.Rules)
	}

	sorted := make([]types.Team, len(teams))
	copy(sorted, teams)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	var bindings strings.Builder
	first := true
	for _, t := range sorted {
		bindingName, ok := BindingName(slug, t.Name, t.Role)
		if !ok {
			continue
		}
		roleName, _ := ClusterRoleName(slug, t.Role)
		if !first {
			bindings.WriteString("---\n")
		}
		first = false
		fmt.Fprintf(&bindings, `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: %s
  labels:
    app.kubernetes.io/managed-by: inari
    inari.io/tenant: %s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: %s
subjects:
  - kind: Group
    name: %s
    apiGroup: rbac.authorization.k8s.io
`, bindingName, slug, roleName, GroupSubjectName(t.KeycloakGroupPath))
	}

	return []gitprovider.File{
		{Path: ClusterRolesPath, Content: []byte(roles.String())},
		{Path: ClusterRoleBindingsPath, Content: []byte(bindings.String())},
	}
}

// RenderRootApp renders the tenant-local ArgoCD root application syncing
// baseline/ from the state repo. It is the minimal slice of
// tenantzonefactory.RenderBaseline needed to make a repo created outside
// the zone flow self-sufficient; keep the shape in sync with TZF's.
func RenderRootApp(repoURL string) gitprovider.File {
	return gitprovider.File{Path: RootAppPath, Content: []byte(fmt.Sprintf(`apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: inari-root
  namespace: argocd
spec:
  project: default
  source:
    repoURL: %s
    targetRevision: HEAD
    path: baseline
  destination:
    server: https://kubernetes.default.svc
    namespace: inari-system
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
`, repoURL))}
}
