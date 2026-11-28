package notifications

import (
	"context"
	"errors"
	"testing"

	"github.com/7K-Inari/inari-server/internal/planlimits"
	"github.com/7K-Inari/inari-server/internal/types"
)

func notificationsDeniedEvaluator() planlimits.Evaluator {
	return planlimits.NewEvaluator(planlimits.ProviderFunc(func(context.Context, string) (planlimits.Limits, error) {
		return planlimits.Limits{}, nil
	}), "")
}

func TestNotificationMutationsHonorPlanLimit(t *testing.T) {
	AllowPrivateEndpoints = true
	t.Cleanup(func() { AllowPrivateEndpoints = false })
	svc := NewService(nil, nil, nil, nil, nil).WithLimitEvaluator(notificationsDeniedEvaluator())
	_, err := svc.CreateEndpoint(context.Background(), "user-1", "org:1", EndpointInput{Name: "alerts", Kind: types.NotificationKindWebhook, URL: "https://example.io/hook"})
	var denied *planlimits.LimitExceededError
	if !errors.As(err, &denied) || denied.Limit != planlimits.GateNotifications {
		t.Fatalf("create error = %T %+v", err, err)
	}
	_, err = svc.UpdateEndpoint(context.Background(), "user-1", "org:1", "nep:1", EndpointInput{Name: "alerts"})
	if !errors.As(err, &denied) {
		t.Fatalf("update error = %T %+v", err, err)
	}
	_, err = svc.TestEndpoint(context.Background(), "user-1", "org:1", "nep:1")
	if !errors.As(err, &denied) {
		t.Fatalf("test error = %T %+v", err, err)
	}
}

func TestNotificationDeliverySkipsDisabledTenant(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil).WithLimitEvaluator(notificationsDeniedEvaluator())
	if err := svc.Handle(context.Background(), &types.OutboxEvent{OrgID: "org:1", EventType: types.EventApprovalRequested}); err != nil {
		t.Fatalf("disabled delivery must be a benign skip: %v", err)
	}
}
