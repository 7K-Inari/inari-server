package approvals

import (
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestPolicyForDefaultsToAuto(t *testing.T) {
	if got := policyFor(&types.CatalogItem{}); got != types.ApprovalPolicyAuto {
		t.Errorf("policyFor zero value = %q, want auto", got)
	}
}

func TestDecisionGuards(t *testing.T) {
	req := &types.ApprovalRequest{
		Requester: "user-alice",
		ItemID:    "curated:postgres-aws",
	}
	item := &types.CatalogItem{ID: req.ItemID, ApprovalPolicy: types.ApprovalPolicyPeer}

	if err := checkApprover(item, req, "user-alice", types.RoleDeveloper); err == nil {
		t.Error("requester must not self-approve under peer policy")
	}
	if err := checkApprover(item, req, "user-bob", types.RoleDeveloper); err != nil {
		t.Errorf("peer approval by another member should pass: %v", err)
	}

	item.ApprovalPolicy = types.ApprovalPolicyPlatformAdmin
	if err := checkApprover(item, req, "user-bob", types.RoleDeveloper); err == nil {
		t.Error("developer must not approve under platform-admin policy")
	}
	if err := checkApprover(item, req, "user-carol", types.RolePlatformEngineer); err != nil {
		t.Errorf("platform engineer should approve: %v", err)
	}
	if err := checkApprover(item, req, "user-dave", types.RoleOrgAdmin); err != nil {
		t.Errorf("org admin should approve: %v", err)
	}

	item.ApprovalPolicy = types.ApprovalPolicyAuto
	if err := checkApprover(item, req, "user-alice", types.RoleViewer); err != nil {
		t.Errorf("auto policy needs no approver constraints: %v", err)
	}
}
