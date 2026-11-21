package orchestrator

import (
	"context"
	"errors"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

type promotionGateSpy struct {
	calls                              int
	orgID, instanceID, version, digest string
	err                                error
}

func (s *promotionGateSpy) CheckPromotion(_ context.Context, orgID, instanceID, version, digest, requester string) error {
	s.calls++
	s.orgID, s.instanceID, s.version, s.digest = orgID, instanceID, version, digest
	return s.err
}

func TestPromotionGateCoversUpgradeButNotRollback(t *testing.T) {
	spy := &promotionGateSpy{err: errors.New("verification required")}
	service := (&Service{}).WithPromotionGate(spy)
	req := DeployRequest{OrgID: "org-1", ArtifactDigest: "sha256:digest"}
	existing := &types.ResourceInstance{ID: "inst-1", Version: "1.0.0"}
	if err := service.checkPromotion(context.Background(), req, existing, types.EventInstanceUpgraded, "1.1.0"); err == nil {
		t.Fatal("upgrade bypassed failed promotion gate")
	}
	if spy.calls != 1 || spy.instanceID != "inst-1" || spy.version != "1.1.0" || spy.digest != req.ArtifactDigest {
		t.Fatalf("gate inputs = %#v", spy)
	}
	if err := service.checkPromotion(context.Background(), req, existing, types.EventInstanceRolledBack, "0.9.0"); err != nil {
		t.Fatalf("explicit rollback incorrectly blocked: %v", err)
	}
	if spy.calls != 1 {
		t.Fatal("rollback invoked automatic verification promotion")
	}
	if err := service.checkPromotion(context.Background(), req, existing, types.EventInstanceUpdated, existing.Version); err != nil || spy.calls != 1 {
		t.Fatal("same-version edit invoked promotion gate")
	}
}
