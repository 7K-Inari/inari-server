package approvals

import (
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestLifecyclePolicy(t *testing.T) {
	deployReq := &types.ApprovalRequest{ItemID: "curated:x"}
	if got := policyForRequest(deployReq, &types.CatalogItem{ApprovalPolicy: types.ApprovalPolicyPeer}); got != types.ApprovalPolicyPeer {
		t.Errorf("deploy request policy = %q, want peer", got)
	}
	lcReq := &types.ApprovalRequest{Action: types.ApprovalActionTenantZoneVend}
	if got := policyForRequest(lcReq, nil); got != types.ApprovalPolicyPlatformAdmin {
		t.Errorf("lifecycle request policy = %q, want platform-admin", got)
	}
}

func TestLifecycleDecisionGuards(t *testing.T) {
	req := &types.ApprovalRequest{
		Action:    types.ApprovalActionTenantZoneDecommission,
		Requester: "user-alice",
	}
	if err := checkLifecycleApprover(req, "user-bob", types.RoleDeveloper); err == nil {
		t.Error("developer must not decide lifecycle approvals")
	}
	if err := checkLifecycleApprover(req, "user-bob", types.RolePlatformEngineer); err != nil {
		t.Errorf("platform engineer decides lifecycle approvals: %v", err)
	}
	if err := checkLifecycleApprover(req, "user-bob", types.RoleOrgAdmin); err != nil {
		t.Errorf("org admin decides lifecycle approvals: %v", err)
	}
	if err := checkLifecycleApprover(req, "user-alice", types.RolePlatformEngineer); err == nil {
		t.Error("requester must not decide their own lifecycle request")
	}
}

func TestValidLifecycleAction(t *testing.T) {
	if !ValidLifecycleAction(types.ApprovalActionTenantZoneVend) {
		t.Error("tenant_zone.vend should be valid")
	}
	if !ValidLifecycleAction(types.ApprovalActionTenantZoneDecommission) {
		t.Error("tenant_zone.decommission should be valid")
	}
	if ValidLifecycleAction("bogus.action") {
		t.Error("unknown action must be rejected")
	}
}
