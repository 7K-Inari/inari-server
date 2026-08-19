package notifications

import (
	"encoding/json"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestFormatMessage(t *testing.T) {
	cases := []struct {
		eventType string
		payload   json.RawMessage
		want      string
	}{
		{types.EventApprovalRequested, mustJSON(t, types.ApprovalPayload{ApprovalID: "ap-1", ItemID: "postgres"}),
			"Approval requested for catalog item postgres (approval ap-1)"},
		{types.EventApprovalDecided, mustJSON(t, types.ApprovalPayload{ApprovalID: "ap-1", ItemID: "postgres", State: "approved"}),
			"Approval ap-1 for catalog item postgres was approved"},
		{types.EventApprovalCancelled, mustJSON(t, types.ApprovalPayload{ApprovalID: "ap-1", ItemID: "postgres"}),
			"Approval ap-1 for catalog item postgres was cancelled"},
		{types.EventApprovalExpired, mustJSON(t, types.ApprovalPayload{ApprovalID: "ap-1", ItemID: "postgres"}),
			"Approval ap-1 for catalog item postgres expired"},
		{types.EventCapabilitiesIngested, mustJSON(t, types.CapabilitiesIngestedPayload{ClusterID: "cluster:1", Upserted: 3, Deleted: 1}),
			"Cluster cluster:1 capabilities updated (3 upserted, 1 deleted)"},
		{types.EventInstanceStatus, mustJSON(t, types.InstancePayload{InstanceID: "inst-1", ClusterID: "cluster:1", Health: "Healthy"}),
			"Instance inst-1 on cluster cluster:1 is now Healthy"},
		{types.EventDeployRequested, mustJSON(t, types.DeployRequestedPayload{ItemID: "postgres", Version: "1.2.0", ClusterID: "cluster:1"}),
			"Deploy of catalog item postgres (version 1.2.0) requested on cluster cluster:1"},
		{types.EventInstanceUpgraded, mustJSON(t, types.InstancePayload{InstanceID: "inst-1", ClusterID: "cluster:1", Version: "1.3.0"}),
			"Instance inst-1 on cluster cluster:1 upgraded to version 1.3.0"},
	}
	for _, tc := range cases {
		got := formatMessage(&types.OutboxEvent{EventType: tc.eventType, Payload: tc.payload})
		if got != tc.want {
			t.Errorf("%s: got %q want %q", tc.eventType, got, tc.want)
		}
	}
}

func TestMatchesEvents(t *testing.T) {
	all := &types.NotificationEndpoint{}
	if !matchesEvents(all, types.EventApprovalRequested) {
		t.Fatal("empty events list must match all events")
	}
	sub := &types.NotificationEndpoint{Events: []string{types.EventApprovalRequested, types.EventApprovalDecided}}
	if !matchesEvents(sub, types.EventApprovalDecided) {
		t.Fatal("expected match for subscribed event")
	}
	if matchesEvents(sub, types.EventInstanceStatus) {
		t.Fatal("expected no match for unsubscribed event")
	}
}

func TestEventTypes(t *testing.T) {
	svc := &Service{}
	got := svc.EventTypes()
	if len(got) != len(subscribedEvents) {
		t.Fatalf("EventTypes len %d, want %d", len(got), len(subscribedEvents))
	}
	for _, e := range got {
		if !knownEvent(e) {
			t.Errorf("EventTypes returned unknown event %q", e)
		}
	}
}

func TestValidateEndpoint(t *testing.T) {
	if err := validateEndpoint(&EndpointInput{Name: "x", Kind: "slack", URL: "https://hooks.slack.com/x"}, ""); err != nil {
		t.Fatal(err)
	}
	if err := validateEndpoint(&EndpointInput{Name: "x", Kind: "pagerduty", URL: "https://x.io"}, ""); err == nil {
		t.Fatal("expected kind error")
	}
	if err := validateEndpoint(&EndpointInput{Name: "x", Kind: "slack", URL: "ftp://x.io"}, ""); err == nil {
		t.Fatal("expected url error")
	}
	if err := validateEndpoint(&EndpointInput{Name: "x", Kind: "slack", URL: "https://x.io", Events: []string{"bogus.event"}}, ""); err == nil {
		t.Fatal("expected event error")
	}
	if err := validateEndpoint(&EndpointInput{Name: "", Kind: "slack", URL: "https://x.io"}, ""); err == nil {
		t.Fatal("expected name error")
	}
}
