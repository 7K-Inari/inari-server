package authz

import (
	"context"
	"slices"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
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

func TestResourceTargetLifecycleTuples(t *testing.T) {
	payload := &types.TenantDeletingPayload{
		OrgID: "org:1", Objects: map[string][]string{TypeResourceTarget: {"rt-1"}},
		TargetGrants: []types.ResourceTargetGrant{{TargetID: "rt-1", TeamID: "team-1", Relation: "provision"}},
	}
	tuples, err := TuplesForTenantDeletion(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(tuples) != 2 {
		t.Fatalf("tuples = %+v, want parent and exact provision grant", tuples)
	}
	if tuples[1].Relation != RelationProvisionGrant || tuples[1].User != TeamMemberUserset("team-1") {
		t.Errorf("grant tuple = %+v", tuples[1])
	}

	fs := &fakeStore{}
	writer := NewTupleWriter(fs)
	if err := writer.Handle(context.Background(), event(t, types.EventTeamDeleted, types.TeamCreatedPayload{
		OrgID: "org:1", TeamID: "team-1", TargetGrants: payload.TargetGrants,
	})); err != nil {
		t.Fatal(err)
	}
	if len(fs.deleted) != 1 || fs.deleted[0].Relation != RelationProvisionGrant {
		t.Errorf("team deletion did not retract target grant: %+v", fs.deleted)
	}
}
