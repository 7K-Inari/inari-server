package clusterdex

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

type spyRenderer struct {
	calls []spyCall
	err   error
}

type spyCall struct {
	orgID      string
	staleNames []string
}

func (s *spyRenderer) RerenderOrg(_ context.Context, orgID string, stale ...string) error {
	s.calls = append(s.calls, spyCall{orgID: orgID, staleNames: stale})
	return s.err
}

type staticFlags struct{ on bool }

func (f staticFlags) Bool(context.Context, string, string) bool { return f.on }

func outboxEvent(t *testing.T, orgID, eventType string, payload any) *types.OutboxEvent {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return &types.OutboxEvent{OrgID: orgID, EventType: eventType, Payload: raw}
}

func TestReconcilerEventTypes(t *testing.T) {
	h := NewReconciler(&spyRenderer{}, nil, nil)
	got := h.EventTypes()
	for _, want := range []string{
		types.EventClusterRegistered, types.EventClusterDeleted,
		types.EventTeamCreated, types.EventTeamDeleted,
		types.EventRBACMappingsUpdated, types.EventTenantCreated,
		"git.webhook.pr_merged",
	} {
		found := false
		for _, et := range got {
			if et == want {
				found = true
			}
		}
		if !found {
			t.Errorf("EventTypes missing %q: %v", want, got)
		}
	}
}

func TestReconcilerRoutesClusterEvents(t *testing.T) {
	spy := &spyRenderer{}
	h := NewReconciler(spy, nil, nil)
	ev := outboxEvent(t, "org:1", types.EventClusterRegistered, types.ClusterPayload{OrgID: "org:1", ClusterID: "c1", Name: "prod-eu"})
	if err := h.Handle(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if len(spy.calls) != 1 || spy.calls[0].orgID != "org:1" {
		t.Fatalf("calls = %+v", spy.calls)
	}
}

func TestReconcilerPassesDeletedClusterName(t *testing.T) {
	spy := &spyRenderer{}
	h := NewReconciler(spy, nil, nil)
	ev := outboxEvent(t, "org:1", types.EventClusterDeleted, types.ClusterPayload{OrgID: "org:1", ClusterID: "c1", Name: "prod-eu"})
	if err := h.Handle(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if len(spy.calls) != 1 || len(spy.calls[0].staleNames) != 1 || spy.calls[0].staleNames[0] != "prod-eu" {
		t.Fatalf("calls = %+v", spy.calls)
	}
}

func TestReconcilerTeamAndRBACEvents(t *testing.T) {
	spy := &spyRenderer{}
	h := NewReconciler(spy, nil, nil)
	for _, et := range []string{types.EventTeamCreated, types.EventTeamDeleted, types.EventRBACMappingsUpdated, types.EventTenantCreated} {
		ev := outboxEvent(t, "org:1", et, map[string]any{"orgId": "org:1"})
		if err := h.Handle(context.Background(), ev); err != nil {
			t.Fatalf("%s: %v", et, err)
		}
	}
	if len(spy.calls) != 4 {
		t.Fatalf("calls = %+v", spy.calls)
	}
}

func TestReconcilerPRMergedUsesRowOrg(t *testing.T) {
	spy := &spyRenderer{}
	h := NewReconciler(spy, nil, nil)
	// The webhook payload carries the repo, not the org; the outbox row's
	// OrgID is authoritative.
	ev := outboxEvent(t, "org:1", "git.webhook.pr_merged", map[string]any{"repo": "acme/acme-inari-state"})
	if err := h.Handle(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if len(spy.calls) != 1 || spy.calls[0].orgID != "org:1" {
		t.Fatalf("calls = %+v", spy.calls)
	}
}

func TestReconcilerFlagOffSkips(t *testing.T) {
	spy := &spyRenderer{}
	h := NewReconciler(spy, staticFlags{on: false}, nil)
	ev := outboxEvent(t, "org:1", types.EventClusterRegistered, types.ClusterPayload{OrgID: "org:1"})
	if err := h.Handle(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if len(spy.calls) != 0 {
		t.Fatalf("flag off must skip: %+v", spy.calls)
	}
}

func TestReconcilerSkipsEmptyOrg(t *testing.T) {
	spy := &spyRenderer{}
	h := NewReconciler(spy, nil, nil)
	ev := outboxEvent(t, "", types.EventClusterRegistered, types.ClusterPayload{})
	if err := h.Handle(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if len(spy.calls) != 0 {
		t.Fatalf("empty org must skip: %+v", spy.calls)
	}
}
