package authz

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

type fakeStore struct {
	written []Tuple
	deleted []Tuple
	checks  map[string]bool
}

func (f *fakeStore) Check(_ context.Context, user, relation, object string) (bool, error) {
	return f.checks[user+"|"+relation+"|"+object], nil
}
func (f *fakeStore) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}
func (f *fakeStore) WriteTuples(_ context.Context, t []Tuple) error {
	f.written = append(f.written, t...)
	return nil
}
func (f *fakeStore) DeleteTuples(_ context.Context, t []Tuple) error {
	f.deleted = append(f.deleted, t...)
	return nil
}

func event(t *testing.T, typ string, payload any) *types.OutboxEvent {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return &types.OutboxEvent{EventType: typ, Payload: raw}
}

func TestTupleWriterTenantCreatedSeedsRoleTuples(t *testing.T) {
	fs := &fakeStore{}
	w := NewTupleWriter(fs)
	ev := event(t, types.EventTenantCreated, types.TenantCreatedPayload{
		OrgID: "org:1",
		Slug:  "acme",
		Teams: []types.TeamSeed{
			{TeamID: "t1", Name: "platform-team", Role: types.RolePlatformEngineer},
			{TeamID: "t2", Name: "devs", Role: types.RoleDeveloper},
		},
	})
	if err := w.Handle(context.Background(), ev); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if len(fs.written) != 2 {
		t.Fatalf("written = %v, want 2 tuples", fs.written)
	}
	if fs.written[0] != (Tuple{User: "team:t1#member", Relation: "platform_engineer", Object: "organization:1"}) {
		t.Errorf("tuple[0] = %+v", fs.written[0])
	}
	if fs.written[1] != (Tuple{User: "team:t2#member", Relation: "developer", Object: "organization:1"}) {
		t.Errorf("tuple[1] = %+v", fs.written[1])
	}
}

func TestTupleWriterMembership(t *testing.T) {
	fs := &fakeStore{}
	w := NewTupleWriter(fs)
	add := event(t, types.EventMembershipAdded, types.MembershipPayload{TeamID: "t1", UserID: "u1"})
	if err := w.Handle(context.Background(), add); err != nil {
		t.Fatalf("Handle add: %v", err)
	}
	if len(fs.written) != 1 || fs.written[0].User != "user:u1" || fs.written[0].Object != "team:t1" {
		t.Errorf("written = %+v", fs.written)
	}
	del := event(t, types.EventMembershipRemoved, types.MembershipPayload{TeamID: "t1", UserID: "u1"})
	if err := w.Handle(context.Background(), del); err != nil {
		t.Fatalf("Handle remove: %v", err)
	}
	if len(fs.deleted) != 1 {
		t.Errorf("deleted = %+v", fs.deleted)
	}
}

func TestAuthorizerDelegates(t *testing.T) {
	fs := &fakeStore{checks: map[string]bool{"user:u1|viewer|organization:org:1": true}}
	a := NewAuthorizer(fs)
	ok, err := a.Check(context.Background(), "user:u1", "viewer", "organization:org:1")
	if err != nil || !ok {
		t.Errorf("Check = %v, %v", ok, err)
	}
	ok, _ = a.Check(context.Background(), "user:u2", "admin", "organization:org:1")
	if ok {
		t.Error("expected deny")
	}
}

func TestTupleWriterTenantZoneLifecycle(t *testing.T) {
	fs := &fakeStore{}
	w := NewTupleWriter(fs)
	act := event(t, types.EventTenantZoneActive, types.TenantZonePayload{
		OrgID: "org:platform", ZoneOrgID: "org:z1", ZoneID: "zone:1", Slug: "acme-dev",
	})
	if err := w.Handle(context.Background(), act); err != nil {
		t.Fatalf("Handle active: %v", err)
	}
	want := Tuple{User: "organization:z1", Relation: "parent", Object: "tenant_zone:zone:1"}
	if len(fs.written) != 1 || fs.written[0] != want {
		t.Fatalf("written = %+v, want [%+v]", fs.written, want)
	}
	cls := event(t, types.EventTenantZoneClosed, types.TenantZonePayload{
		OrgID: "org:platform", ZoneOrgID: "org:z1", ZoneID: "zone:1",
	})
	if err := w.Handle(context.Background(), cls); err != nil {
		t.Fatalf("Handle closed: %v", err)
	}
	if len(fs.deleted) != 1 || fs.deleted[0] != want {
		t.Fatalf("deleted = %+v, want [%+v]", fs.deleted, want)
	}
}
