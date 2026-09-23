package authz

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

// TestTupleWriterRestoresSweptTuples pins the decommission-denied fix: a
// tenant.restored event must re-write exactly the tuples that
// tenant.deleting swept (same snapshot, write direction).
func TestTupleWriterRestoresSweptTuples(t *testing.T) {
	p := types.TenantDeletingPayload{
		OrgID: "org:1",
		Slug:  "acme",
		Teams: []types.TeamSeed{{TeamID: "team-1", Name: "core", Role: types.RoleOrgAdmin}},
		Members: []types.MembershipPayload{
			{OrgID: "org:1", TeamID: "team-1", UserID: "user-1", Role: types.RoleOrgAdmin},
		},
		Objects: map[string][]string{"cluster": {"clu-1"}},
	}
	payload, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	st := &syncStore{}
	w := NewTupleWriter(st)

	if err := w.Handle(context.Background(), &types.OutboxEvent{EventType: types.EventTenantDeleting, Payload: payload}); err != nil {
		t.Fatalf("deleting: %v", err)
	}
	if err := w.Handle(context.Background(), &types.OutboxEvent{EventType: types.EventTenantRestored, Payload: payload}); err != nil {
		t.Fatalf("restored: %v", err)
	}
	if len(st.deleted) == 0 {
		t.Fatal("tenant.deleting wrote no delete tuples")
	}
	if len(st.written) != len(st.deleted) {
		t.Fatalf("restored %d tuples, sweep deleted %d — restore must re-seed the full snapshot", len(st.written), len(st.deleted))
	}
	want := map[Tuple]bool{}
	for _, tup := range st.deleted {
		want[tup] = true
	}
	for _, tup := range st.written {
		if !want[tup] {
			t.Errorf("restored tuple %+v was not in the swept set", tup)
		}
	}
	for _, et := range w.EventTypes() {
		if et == types.EventTenantRestored {
			return
		}
	}
	t.Error("tenant.restored not registered in EventTypes")
}
