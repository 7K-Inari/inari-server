package notifications

import (
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestVerificationEventFilteringAndMessage(t *testing.T) {
	payload := mustJSON(t, map[string]any{"runId": "vr-1", "status": "failed", "notificationEndpointIds": []string{"nep-1"}, "automaticRollback": false})
	if !verificationEndpointSelected(payload, "nep-1") || verificationEndpointSelected(payload, "nep-2") {
		t.Fatal("verification endpoint selection mismatch")
	}
	if verificationEndpointSelected([]byte(`{"notificationEndpointIds":[]}`), "nep-1") {
		t.Fatal("empty policy recipient list notified an endpoint")
	}
	message := formatMessage(&types.OutboxEvent{EventType: types.EventVerificationFailed, Payload: payload})
	if !strings.Contains(message, "vr-1") || !strings.Contains(message, "No automatic rollback") {
		t.Fatalf("verification message = %q", message)
	}
	for _, event := range []string{types.EventVerificationRunStarted, types.EventVerificationPassed, types.EventVerificationFailed, types.EventVerificationBlocked, types.EventVerificationPromotionBlocked} {
		if !knownEvent(event) {
			t.Errorf("verification event %q is not subscribed", event)
		}
	}
}
