// Package rbacmaterialize closes the RBAC-mapping chain (plan §7.1,
// ADR-0013): it renders one ClusterRole per org role
// (tenant-<slug>-<role.Name>; the four built-ins preserve the pinned
// tenant-<slug>-{admin,operator,editor,viewer} contract) plus one
// role-qualified ClusterRoleBinding per team mapping
// (tenant-<slug>-<team>-<role>; role-qualified because roleRef is
// immutable — a mapping flip must create a new object and prune the old
// one, never update in place) as desired state into the tenant's
// <slug>-inari-state repo under baseline/rbac/ — the tenant-local ArgoCD
// root app syncs only baseline/, so committing there is sufficient for
// convergence (same constraint as secretstores.stateRepoPath). Role names
// are pinned to the RBAC matrix API contract (tenancy identity_http.go
// synthesizes the same names from the roles table).
package rbacmaterialize

import (
	"fmt"
	"sort"
	"strings"

	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// State repo paths (must stay under baseline/ — see package doc).
const (
	ClusterRolesPath        = "baseline/rbac/clusterroles.yaml"
	ClusterRoleBindingsPath = "baseline/rbac/clusterrolebindings.yaml"
	RootAppPath             = "baseline/argocd/root-app.yaml"
)

// k8sFragments are the rule fragments a role's permission bundle unions
// into (authz.EffectiveK8sTier picks the highest tier). The texts are
// byte-pinned: the built-in roles must render the exact rules the retired
// anchor roles rendered (ADR-0013). Tenant-plane-only permission sets
// contribute no rules (empty ClusterRole).
var k8sFragments = map[string]string{
	// admin: full tenant administration — cluster-admin equivalent (the
	// tenant cluster is dedicated to the tenant).
	"admin": `
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
  - nonResourceURLs: ["*"]
    verbs: ["*"]`,
	// operator: edit workload resources + operate the tenant's GitOps and
	// infrastructure CRs (ArgoCD apps, Crossplane claims, kro instances).
	"operator": `
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["argoproj.io"]
    resources: ["applications", "applicationsets", "appprojects"]
    verbs: ["*"]
  - apiGroups: ["apiextensions.crossplane.io", "pkg.crossplane.io", "kro.run"]
    resources: ["*"]
    verbs: ["*"]`,
	// editor: deploy and edit resources.
	"editor": `
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]`,
	// viewer: read-only.
	"viewer": `
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["get", "list", "watch"]`,
}

// ClusterRoleName returns the ClusterRole an org role renders
// (tenant-<slug>-<role.Name>).
func ClusterRoleName(slug, roleName string) string {
	return "tenant-" + slug + "-" + roleName
}

// BindingName returns the ClusterRoleBinding for a team mapping. The name
// is role-qualified (tenant-<slug>-<team>-<role>) because roleRef is
// immutable: a mapping change must produce a NEW binding object (the
// ArgoCD root app prunes the stale one) instead of an in-place update the
// API server rejects.
func BindingName(slug, team, roleName string) string {
	return "tenant-" + slug + "-" + team + "-" + roleName
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
// baseline/rbac/clusterroles.yaml (one ClusterRole per org role, document
// order by role name for determinism) and
// baseline/rbac/clusterrolebindings.yaml (one role-qualified binding per
// team, sorted by team name so an unchanged desired state produces no git
// diff; a role change renders a new binding name and the ArgoCD root app
// prunes the stale one — roleRef is immutable, so in-place flips are
// rejected by the API server).
func RenderTenantRBAC(slug string, roles []types.Role, teams []types.Team) []gitprovider.File {
	sortedRoles := make([]types.Role, len(roles))
	copy(sortedRoles, roles)
	sort.Slice(sortedRoles, func(i, j int) bool { return sortedRoles[i].Name < sortedRoles[j].Name })

	var clusterRoles strings.Builder
	for i, r := range sortedRoles {
		if i > 0 {
			clusterRoles.WriteString("---\n")
		}
		rules := " []"
		if fragment, ok := k8sFragments[authz.EffectiveK8sTier(r.Permissions)]; ok {
			rules = fragment
		}
		fmt.Fprintf(&clusterRoles, `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: %s
  labels:
    app.kubernetes.io/managed-by: inari
    inari.io/tenant: %s
rules:%s
`, ClusterRoleName(slug, r.Name), slug, rules)
	}

	sorted := make([]types.Team, len(teams))
	copy(sorted, teams)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	var bindings strings.Builder
	first := true
	for _, t := range sorted {
		if t.RoleName == "" {
			continue
		}
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
`, BindingName(slug, t.Name, t.RoleName), slug, ClusterRoleName(slug, t.RoleName), GroupSubjectName(t.KeycloakGroupPath))
	}

	return []gitprovider.File{
		{Path: ClusterRolesPath, Content: []byte(clusterRoles.String())},
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
