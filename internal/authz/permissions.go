// Permission catalog (ADR-0013): the static, server-owned set of permission
// slugs the OpenFGA model encodes — one organization relation per slug,
// granted via [team#member] usersets. Roles are dynamic DB rows bundling
// these slugs; the model never changes on role CRUD. FGA relation names
// cannot contain '.', so each slug maps to an underscored relation via
// PermissionRelation (tenant.settings.write → tenant_settings_write).
package authz

import "strings"

// Permission slugs (API contract: roles carry these strings; the
// permissions/catalog endpoint serves them to the role editor UI).
const (
	PermTenantRead                = "tenant.read"
	PermTenantSettingsWrite       = "tenant.settings.write"
	PermTenantMembersManage       = "tenant.members.manage"
	PermTenantTeamsManage         = "tenant.teams.manage"
	PermTenantRBACManage          = "tenant.rbac.manage"
	PermTenantIdentityManage      = "tenant.identity.manage"
	PermTenantNotificationsManage = "tenant.notifications.manage"
	PermTenantAdmin               = "tenant.admin"
	PermClustersRegister          = "clusters.register"
	PermClustersKubectl           = "clusters.kubectl"
	PermCloudAccountsManage       = "cloudaccounts.manage"
	PermZonesManage               = "zones.manage"
	PermFleetManage               = "fleet.manage"
	PermPoliciesManage            = "policies.manage"
	PermSecretStoresManage        = "secretstores.manage"
	PermExtensionsManage          = "extensions.manage"
	PermExtensionsInvoke          = "extensions.invoke"
	PermCatalogManage             = "catalog.manage"
	PermDeploymentsCreate         = "deployments.create"
	PermApprovalsManage           = "approvals.manage"
)

// FGA relation constants for the organization permission relations (the
// PEP call sites reference these, mirroring the retired RelationViewer/
// RelationPlatformEngineer/RelationDeveloper/RelationAdmin style).
const (
	RelationTenantRead                = "tenant_read"
	RelationTenantSettingsWrite       = "tenant_settings_write"
	RelationTenantMembersManage       = "tenant_members_manage"
	RelationTenantTeamsManage         = "tenant_teams_manage"
	RelationTenantRBACManage          = "tenant_rbac_manage"
	RelationTenantIdentityManage      = "tenant_identity_manage"
	RelationTenantNotificationsManage = "tenant_notifications_manage"
	RelationTenantAdmin               = "tenant_admin"
	RelationClustersRegister          = "clusters_register"
	RelationClustersKubectl           = "clusters_kubectl"
	// RelationKubectl is the cluster-object relation the kubeproxy PEP
	// checks per proxied request (derived from clusters_kubectl via parent).
	RelationKubectl = "kubectl"
	RelationCloudAccountsManage       = "cloudaccounts_manage"
	RelationZonesManage               = "zones_manage"
	RelationFleetManage               = "fleet_manage"
	RelationPoliciesManage            = "policies_manage"
	RelationSecretStoresManage        = "secretstores_manage"
	RelationExtensionsManage          = "extensions_manage"
	RelationExtensionsInvoke          = "extensions_invoke"
	RelationCatalogManage             = "catalog_manage"
	RelationDeploymentsCreate         = "deployments_create"
	RelationApprovalsManage           = "approvals_manage"
)

// Permission is one catalog entry served to the role editor UI.
type Permission struct {
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// Domain groups the checklist in the role editor
	// (tenant | infrastructure | workloads).
	Domain string `json:"domain"`
	// k8sFragment is the rbacmaterialize rule-fragment tier this permission
	// contributes (admin | operator | editor | viewer; empty = tenant-plane
	// only, no Kubernetes rules).
	k8sFragment string
}

// PermissionCatalog returns the full static catalog in stable order.
func PermissionCatalog() []Permission {
	return []Permission{
		{PermTenantRead, "Read tenant", "View the tenant, its resources, and status", "tenant", "viewer"},
		{PermTenantSettingsWrite, "Edit tenant settings", "Update the org profile and git configuration", "tenant", ""},
		{PermTenantMembersManage, "Manage members", "Invite and remove org and team members", "tenant", ""},
		{PermTenantTeamsManage, "Manage teams", "Create, update, and delete teams", "tenant", ""},
		{PermTenantRBACManage, "Manage RBAC", "Edit roles and team-to-role mappings", "tenant", ""},
		{PermTenantIdentityManage, "Manage identity", "Manage OIDC clients and identity-provider brokers", "tenant", ""},
		{PermTenantNotificationsManage, "Manage notifications", "Configure notification channels and rules", "tenant", ""},
		{PermTenantAdmin, "Tenant administrator", "Delete the tenant and other irreversible administration", "tenant", "admin"},
		{PermClustersRegister, "Operate clusters", "Register, cordon, and decommission clusters", "infrastructure", "operator"},
		{PermClustersKubectl, "Access clusters with kubectl", "Open proxied kubectl sessions through the inari-kubeproxy gateway", "infrastructure", ""},
		{PermCloudAccountsManage, "Manage cloud accounts", "Register and deregister cloud accounts", "infrastructure", "operator"},
		{PermZonesManage, "Manage tenant zones", "Provision and close tenant zones", "infrastructure", "operator"},
		{PermFleetManage, "Manage fleet", "Operate the cluster fleet (cluster sets, rollouts, drift)", "infrastructure", "operator"},
		{PermPoliciesManage, "Manage policies", "Create, assign, and delete policy packs", "infrastructure", "operator"},
		{PermSecretStoresManage, "Manage secret stores", "Configure external secret stores", "infrastructure", "operator"},
		{PermExtensionsManage, "Manage extensions", "Register and unregister extensions", "infrastructure", "operator"},
		{PermExtensionsInvoke, "Invoke extensions", "Call extension backends through the gateway proxy", "workloads", ""},
		{PermCatalogManage, "Manage catalog", "Publish and edit org catalog items", "workloads", "editor"},
		{PermDeploymentsCreate, "Deploy workloads", "Deploy, update, roll back, and undeploy instances; run scaffolds", "workloads", "editor"},
		{PermApprovalsManage, "Manage approvals", "Decide approval requests and configure approval policy", "workloads", ""},
	}
}

// catalogIndex maps slug → catalog entry (built once).
var catalogIndex = func() map[string]Permission {
	m := make(map[string]Permission, 20)
	for _, p := range PermissionCatalog() {
		m[p.Slug] = p
	}
	return m
}()

// ValidPermission reports whether slug is in the static catalog.
func ValidPermission(slug string) bool {
	_, ok := catalogIndex[slug]
	return ok
}

// PermissionRelation maps a catalog slug to its FGA organization relation
// (dots → underscores); ok is false for unknown slugs.
func PermissionRelation(slug string) (string, bool) {
	if !ValidPermission(slug) {
		return "", false
	}
	return strings.ReplaceAll(slug, ".", "_"), true
}

// K8sFragmentTier returns the rbacmaterialize rule-fragment tier a
// permission contributes ("admin", "operator", "editor", "viewer"; "" for
// tenant-plane-only permissions and unknown slugs).
func K8sFragmentTier(slug string) string {
	p, ok := catalogIndex[slug]
	if !ok {
		return ""
	}
	return p.k8sFragment
}

// k8sTierRank orders the rule fragments from least to most privileged;
// a role's ClusterRole renders the highest fragment any of its permissions
// contributes (rbacmaterialize rule union).
var k8sTierRank = map[string]int{"": 0, "viewer": 1, "editor": 2, "operator": 3, "admin": 4}

// EffectiveK8sTier returns the highest k8s rule-fragment tier across a
// permission set ("" when no permission contributes Kubernetes rules).
func EffectiveK8sTier(permissions []string) string {
	best := ""
	for _, p := range permissions {
		if k8sTierRank[K8sFragmentTier(p)] > k8sTierRank[best] {
			best = K8sFragmentTier(p)
		}
	}
	return best
}

// BuiltinRole is one seeded, deletion-protected default role. Names double
// as the ClusterRole suffix (tenant-<slug>-<name>) so the four built-ins
// preserve the pinned tenant-<slug>-{admin,operator,editor,viewer}
// contract; keep in sync with migration 0029's seed.
type BuiltinRole struct {
	Name        string
	DisplayName string
	Description string
	Permissions []string
}

// BuiltinRoleNames are the built-in role identifiers (URL segment of the
// roles API and the ClusterRole suffix).
const (
	BuiltinRoleAdmin    = "admin"
	BuiltinRoleOperator = "operator"
	BuiltinRoleEditor   = "editor"
	BuiltinRoleViewer   = "viewer"
)

// BuiltinRoles returns the four seeded default roles with their permission
// bundles mirroring the retired hierarchy
// (org-admin ⊇ platform-engineer ⊇ developer ⊇ viewer).
func BuiltinRoles() []BuiltinRole {
	all := make([]string, 0, 20)
	for _, p := range PermissionCatalog() {
		all = append(all, p.Slug)
	}
	operator := []string{
		PermTenantRead, PermTenantMembersManage,
		PermClustersRegister, PermClustersKubectl, PermCloudAccountsManage, PermZonesManage,
		PermFleetManage, PermPoliciesManage, PermSecretStoresManage,
		PermExtensionsManage, PermExtensionsInvoke,
		PermCatalogManage, PermDeploymentsCreate, PermApprovalsManage,
	}
	editor := []string{
		PermTenantRead, PermCatalogManage, PermDeploymentsCreate,
		PermExtensionsInvoke, PermApprovalsManage,
	}
	viewer := []string{PermTenantRead}
	return []BuiltinRole{
		{BuiltinRoleAdmin, "Org Admin", "Full tenant administration", all},
		{BuiltinRoleOperator, "Platform Engineer", "Operate the tenant's clusters, infrastructure, and workloads", operator},
		{BuiltinRoleEditor, "Developer", "Deploy and manage workloads", editor},
		{BuiltinRoleViewer, "Viewer", "Read-only access", viewer},
	}
}

// BuiltinRolePermissions returns the seeded bundle for a built-in role name
// (nil for unknown names).
func BuiltinRolePermissions(name string) []string {
	for _, r := range BuiltinRoles() {
		if r.Name == name {
			return r.Permissions
		}
	}
	return nil
}
