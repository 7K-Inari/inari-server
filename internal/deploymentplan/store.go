package deploymentplan

import (
	"context"
	"errors"
	"fmt"

	observability "github.com/7K-Inari/inari-api/contract/observability/v1"
)

var (
	ErrPlanNotFound        = errors.New("deployment plan not found")
	ErrCompanionNotFound   = errors.New("observability companion not found")
	ErrPlanConflict        = errors.New("deployment plan conflict")
	ErrIdempotencyConflict = fmt.Errorf("%w: idempotency key already exists", ErrPlanConflict)
)

func verificationToken(result *observability.VerificationResult) string {
	if result == nil {
		return ""
	}
	return fmt.Sprintf("%d:%s:%d:%s", result.Companion.Generation, result.Run.ID, result.Run.Attempt, result.Suite.Digest)
}

// Store is the persistence seam. SQL implementation lives in store_sql.go;
// unit tests use the in-memory implementation in store_memory.go.
type Store interface {
	CreatePlan(ctx context.Context, plan *Plan) error
	UpdatePlan(ctx context.Context, plan *Plan) error
	GetPlan(ctx context.Context, orgID, id string) (*Plan, error)
	GetPlanByIdempotency(ctx context.Context, orgID, requester, key string) (*Plan, error)
	LatestPlanForInstance(ctx context.Context, orgID, instanceID string) (*Plan, error)
	GetCompanion(ctx context.Context, orgID, id string) (*Companion, error)
	LatestCompanionForInstance(ctx context.Context, orgID, instanceID string) (*Companion, error)
	SaveVerification(ctx context.Context, orgID string, companion *Companion, result *observability.VerificationResult, expectedVerification string) (bool, error)
}
