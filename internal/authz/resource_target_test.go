package authz

import (
	"slices"
	"testing"
)

func TestResourceTargetModelAndPermissions(t *testing.T) {
	if !ValidPermission(PermResourceTargetsManage) {
		t.Fatal("resourcetargets.manage must be in the static permission catalog")
	}
	if got := K8sFragmentTier(PermResourceTargetsManage); got != "" {
		t.Errorf("target management leaked into Kubernetes RBAC tier %q", got)
	}
	for _, role := range []string{BuiltinRoleAdmin, BuiltinRoleOperator} {
		if !slices.Contains(BuiltinRolePermissions(role), PermResourceTargetsManage) {
			t.Errorf("%s role missing target management", role)
		}
	}
	if slices.Contains(BuiltinRolePermissions(BuiltinRoleEditor), PermResourceTargetsManage) {
		t.Fatal("editor must not manage resource targets")
	}

	td := typeDef(t, TypeResourceTarget)
	rels := *td.Relations
	for _, relation := range []string{RelationParent, RelationManage, RelationViewGrant, RelationUseGrant, RelationProvisionGrant, RelationViewer, RelationUse, RelationProvision} {
		if _, ok := rels[relation]; !ok {
			t.Errorf("resource_target missing %s", relation)
		}
	}
	if rels[RelationManage].TupleToUserset == nil || *rels[RelationManage].TupleToUserset.ComputedUserset.Relation != RelationResourceTargetsManage {
		t.Errorf("manage must derive from org permission: %+v", rels[RelationManage])
	}
	for _, relation := range []string{RelationViewGrant, RelationUseGrant, RelationProvisionGrant} {
		if rels[relation].This == nil {
			t.Errorf("%s must be a direct team grant", relation)
		}
	}
	if ResourceTargetObject("rt-1") != "resource_target:rt-1" {
		t.Errorf("unexpected object %q", ResourceTargetObject("rt-1"))
	}
}
