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

	if err := checkApprover(item, req, "user-alice", true); err == nil {
		t.Error("requester must not self-approve under peer policy")
	}
	if err := checkApprover(item, req, "user-bob", false); err != nil {
		t.Errorf("peer approval by another member should pass: %v", err)
	}

	item.ApprovalPolicy = types.ApprovalPolicyPlatformAdmin
	if err := checkApprover(item, req, "user-bob", false); err == nil {
		t.Error("approver without the platform-operations floor must not approve under platform-admin policy")
	}
	if err := checkApprover(item, req, "user-carol", true); err != nil {
		t.Errorf("platform-operations approver should approve: %v", err)
	}

	item.ApprovalPolicy = types.ApprovalPolicyAuto
	if err := checkApprover(item, req, "user-alice", false); err != nil {
		t.Errorf("auto policy needs no approver constraints: %v", err)
	}
}
