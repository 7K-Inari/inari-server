package authz

import (
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestTuplesForTenantDeletion(t *testing.T) {
	p := &types.TenantDeletingPayload{
		OrgID: "org:kc-1",
		Slug:  "acme",
		Teams: []types.TeamSeed{
			{TeamID: "t1", Name: "platform-team", Role: types.RolePlatformEngineer},
			{TeamID: "t2", Name: "viewers", Role: types.RoleViewer},
		},
		Members: []types.MembershipPayload{
			{OrgID: "org:kc-1", TeamID: "t1", UserID: "u1", Role: types.RolePlatformEngineer},
		},
		Objects: map[string][]string{
			"cluster":       {"c1"},
			"cloud_account": {"cloudaccount:a1"},
			"tenant_zone":   {"zone:z1"},
			"drift_event":   {"drift:d1"},
		},
	}
	tuples, err := TuplesForTenantDeletion(p)
	if err != nil {
		t.Fatal(err)
	}
	want := map[Tuple]bool{
		{User: "team:t1#member", Relation: "platform_engineer", Object: "organization:kc-1"}:     false,
		{User: "team:t2#member", Relation: "viewer", Object: "organization:kc-1"}:                false,
		{User: "user:u1", Relation: "member", Object: "team:t1"}:                                 false,
		{User: "organization:kc-1", Relation: "parent", Object: "cluster:c1"}:                    false,
		{User: "organization:kc-1", Relation: "parent", Object: "cloud_account:cloudaccount:a1"}: false,
		{User: "organization:kc-1", Relation: "parent", Object: "tenant_zone:zone:z1"}:           false,
		{User: "organization:kc-1", Relation: "parent", Object: "drift_event:drift:d1"}:          false,
	}
	if len(tuples) != len(want) {
		t.Fatalf("tuples = %d, want %d: %+v", len(tuples), len(want), tuples)
	}
	for _, tup := range tuples {
		if _, ok := want[tup]; !ok {
			t.Errorf("unexpected tuple %+v", tup)
		}
	}
}

func TestTuplesForTenantDeletionUnknownType(t *testing.T) {
	p := &types.TenantDeletingPayload{
		OrgID:   "org:1",
		Objects: map[string][]string{"bogus": {"x"}},
	}
	if _, err := TuplesForTenantDeletion(p); err == nil {
		t.Fatal("expected error for unknown object type")
	}
}

func TestTupleWriterTenantDeletingSweep(t *testing.T) {
	fs := &fakeStore{}
	w := NewTupleWriter(fs)
	p := types.TenantDeletingPayload{
		OrgID: "org:1",
		Teams: []types.TeamSeed{{TeamID: "t9", Name: "devs", Role: types.RoleDeveloper}},
	}
	ev := event(t, types.EventTenantDeleting, p)
	if err := w.Handle(t.Context(), ev); err != nil {
		t.Fatal(err)
	}
	if len(fs.deleted) != 1 {
		t.Fatalf("deleted = %d, want 1", len(fs.deleted))
	}
	want := Tuple{User: "team:t9#member", Relation: "developer", Object: "organization:1"}
	if fs.deleted[0] != want {
		t.Errorf("deleted[0] = %+v, want %+v", fs.deleted[0], want)
	}
	// Event is registered.
	found := false
	for _, et := range w.EventTypes() {
		if et == types.EventTenantDeleting {
			found = true
		}
	}
	if !found {
		t.Error("EventTenantDeleting not registered in EventTypes")
	}
}
