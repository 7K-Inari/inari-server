package deploymentplan

import (
	"context"
	"sync"

	observability "github.com/7K-Inari/inari-api/contract/observability/v1"
)

// MemoryStore is a concurrency-safe test/fixture store.
type MemoryStore struct {
	mu            sync.RWMutex
	plans         map[string]*Plan
	companions    map[string]*Companion
	verifications map[string]*observability.VerificationResult
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{plans: map[string]*Plan{}, companions: map[string]*Companion{}, verifications: map[string]*observability.VerificationResult{}}
}

func clonePlan(plan *Plan) *Plan {
	if plan == nil {
		return nil
	}
	return plan.DeepCopy()
}

func (s *MemoryStore) CreatePlan(_ context.Context, plan *Plan) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.plans[plan.ID]; exists {
		return ErrPlanConflict
	}
	s.plans[plan.ID] = clonePlan(plan)
	if plan.Companion != nil {
		s.companions[plan.Companion.ID] = plan.Companion.DeepCopy()
	}
	return nil
}

func (s *MemoryStore) UpdatePlan(_ context.Context, plan *Plan) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.plans[plan.ID]; !exists {
		return ErrPlanNotFound
	}
	s.plans[plan.ID] = clonePlan(plan)
	if plan.Companion != nil {
		s.companions[plan.Companion.ID] = plan.Companion.DeepCopy()
	}
	return nil
}

func (s *MemoryStore) GetPlan(_ context.Context, orgID, id string) (*Plan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	plan := s.plans[id]
	if plan == nil || plan.OrgID != orgID {
		return nil, ErrPlanNotFound
	}
	return clonePlan(plan), nil
}

func (s *MemoryStore) GetPlanByIdempotency(_ context.Context, orgID, requester, key string) (*Plan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, plan := range s.plans {
		if plan.OrgID == orgID && plan.Requester == requester && plan.IdempotencyKey == key {
			return clonePlan(plan), nil
		}
	}
	return nil, ErrPlanNotFound
}

func (s *MemoryStore) LatestPlanForInstance(_ context.Context, orgID, instanceID string) (*Plan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var found *Plan
	for _, plan := range s.plans {
		if plan.OrgID == orgID && plan.AppInstanceID == instanceID && (found == nil || plan.UpdatedAt.After(found.UpdatedAt)) {
			found = plan
		}
	}
	if found == nil {
		return nil, ErrPlanNotFound
	}
	return clonePlan(found), nil
}

func (s *MemoryStore) GetCompanion(_ context.Context, orgID, id string) (*Companion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	companion := s.companions[id]
	if companion == nil {
		return nil, ErrCompanionNotFound
	}
	plan := s.plans[companion.PlanID]
	if plan == nil || plan.OrgID != orgID {
		return nil, ErrCompanionNotFound
	}
	return companion.DeepCopy(), nil
}

func (s *MemoryStore) LatestCompanionForInstance(_ context.Context, orgID, instanceID string) (*Companion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var found *Companion
	for _, companion := range s.companions {
		plan := s.plans[companion.PlanID]
		if plan != nil && plan.OrgID == orgID && companion.AppInstanceID == instanceID && (found == nil || companion.UpdatedAt.After(found.UpdatedAt)) {
			found = companion
		}
	}
	if found == nil {
		return nil, ErrCompanionNotFound
	}
	return found.DeepCopy(), nil
}

func (s *MemoryStore) SaveVerification(_ context.Context, companionID string, result *observability.VerificationResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifications[companionID] = result
	return nil
}
