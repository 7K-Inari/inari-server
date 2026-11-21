package orchestrator

import (
	"context"

	"github.com/7K-Inari/inari-server/internal/types"
)

// PromotionGate is the verification evidence predicate. It never performs a
// deployment or rollback itself.
type PromotionGate interface {
	CheckPromotion(ctx context.Context, orgID, instanceID, toVersion, toDigest, requester string) error
}

func (s *Service) WithPromotionGate(gate PromotionGate) *Service {
	s.promotionGate = gate
	return s
}

func (s *Service) checkPromotion(ctx context.Context, req DeployRequest, existing *types.ResourceInstance, eventType, version string) error {
	if s.promotionGate == nil || existing == nil || existing.Version == version || eventType == types.EventInstanceRolledBack {
		return nil
	}
	return s.promotionGate.CheckPromotion(ctx, req.OrgID, existing.ID, version, req.ArtifactDigest, req.Requester)
}
