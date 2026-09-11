package authz

import (
	"context"
	"errors"
	"testing"
)

// pathMemberLister fakes Keycloak group membership keyed by group path.
type pathMemberLister struct {
	byPath map[string][]string
	errs   map[string]error
}

func (f *pathMemberLister) ListGroupMembers(_ context.Context, path string) ([]string, error) {
	if err := f.errs[path]; err != nil {
		return nil, err
	}
	return f.byPath[path], nil
}

type fakeTeamGroupLister struct{ groups []TeamGroupRef }

func (f *fakeTeamGroupLister) ListTeamGroups(context.Context) ([]TeamGroupRef, error) {
	return f.groups, nil
}

func TestOrgTeamSyncWritesNewMembers(t *testing.T) {
	st := &syncStore{}
	syncer := NewOrgTeamSync(st,
		&pathMemberLister{byPath: map[string][]string{"tenant-acme/members": {"u1", "u2"}}},
		&fakeTeamGroupLister{groups: []TeamGroupRef{{TeamID: "t1", GroupPath: "tenant-acme/members"}}})
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	if len(st.written) != 2 {
		t.Fatalf("written = %+v, want 2", st.written)
	}
	for _, tup := range st.written {
		if tup.Relation != RelationMember || tup.Object != TeamObject("t1") {
			t.Errorf("tuple = %+v, want member on team:t1", tup)
		}
	}
	if len(st.deleted) != 0 {
		t.Errorf("deleted = %+v, want none", st.deleted)
	}
}

func TestOrgTeamSyncDeletesRemovedMembers(t *testing.T) {
	st := &syncStore{existing: []Tuple{
		{User: "user:u1", Relation: RelationMember, Object: TeamObject("t1")},
		{User: "user:u2", Relation: RelationMember, Object: TeamObject("t1")},
	}}
	syncer := NewOrgTeamSync(st,
		&pathMemberLister{byPath: map[string][]string{"tenant-acme/members": {"u1"}}},
		&fakeTeamGroupLister{groups: []TeamGroupRef{{TeamID: "t1", GroupPath: "tenant-acme/members"}}})
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	if len(st.deleted) != 1 || st.deleted[0].User != "user:u2" {
		t.Errorf("deleted = %+v, want [user:u2]", st.deleted)
	}
	if len(st.written) != 0 {
		t.Errorf("written = %+v, want none", st.written)
	}
}

func TestOrgTeamSyncMultiTenant(t *testing.T) {
	st := &syncStore{existing: []Tuple{
		// Stale tuple on org B's team: user left the KC group.
		{User: "user:old", Relation: RelationMember, Object: TeamObject("tb")},
		// Platform tuples are never touched by the org-team reconciler.
		{User: "user:root", Relation: RelationOrgCreator, Object: ObjectPlatform},
	}}
	syncer := NewOrgTeamSync(st,
		&pathMemberLister{byPath: map[string][]string{
			"tenant-acme/members":    {"u1"},
			"tenant-acme/developers": {"u1", "u2"},
			"tenant-globex/members":  {},
		}},
		&fakeTeamGroupLister{groups: []TeamGroupRef{
			{TeamID: "ta1", GroupPath: "tenant-acme/members"},
			{TeamID: "ta2", GroupPath: "tenant-acme/developers"},
			{TeamID: "tb", GroupPath: "tenant-globex/members"},
		}})
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	if len(st.written) != 3 {
		t.Errorf("written = %+v, want 3 (u1→ta1, u1+u2→ta2)", st.written)
	}
	if len(st.deleted) != 1 || st.deleted[0].User != "user:old" || st.deleted[0].Object != TeamObject("tb") {
		t.Errorf("deleted = %+v, want [user:old on team:tb]", st.deleted)
	}
}

func TestOrgTeamSyncIdempotent(t *testing.T) {
	st := &syncStore{existing: []Tuple{
		{User: "user:u1", Relation: RelationMember, Object: TeamObject("t1")},
	}}
	syncer := NewOrgTeamSync(st,
		&pathMemberLister{byPath: map[string][]string{"tenant-acme/members": {"u1"}}},
		&fakeTeamGroupLister{groups: []TeamGroupRef{{TeamID: "t1", GroupPath: "tenant-acme/members"}}})
	for i := 0; i < 2; i++ {
		if err := syncer.SyncOnce(context.Background()); err != nil {
			t.Fatalf("SyncOnce: %v", err)
		}
	}
	if len(st.written) != 0 || len(st.deleted) != 0 {
		t.Errorf("written=%+v deleted=%+v, want no-ops", st.written, st.deleted)
	}
}

// A failing group must not starve other tenants: the error is joined and
// returned, the remaining groups are still reconciled.
func TestOrgTeamSyncGroupErrorIsolation(t *testing.T) {
	st := &syncStore{}
	syncer := NewOrgTeamSync(st,
		&pathMemberLister{
			byPath: map[string][]string{"tenant-globex/members": {"u9"}},
			errs:   map[string]error{"tenant-acme/members": errors.New("keycloak down")},
		},
		&fakeTeamGroupLister{groups: []TeamGroupRef{
			{TeamID: "ta", GroupPath: "tenant-acme/members"},
			{TeamID: "tb", GroupPath: "tenant-globex/members"},
		}})
	if err := syncer.SyncOnce(context.Background()); err == nil {
		t.Fatal("SyncOnce: want joined error for the failing group")
	}
	if len(st.written) != 1 || st.written[0].Object != TeamObject("tb") {
		t.Errorf("written = %+v, want the healthy group's member", st.written)
	}
}

// Teams without a Keycloak group path (never materialized) are skipped.
func TestOrgTeamSyncSkipsEmptyGroupPath(t *testing.T) {
	st := &syncStore{}
	syncer := NewOrgTeamSync(st,
		&pathMemberLister{byPath: map[string][]string{}},
		&fakeTeamGroupLister{groups: []TeamGroupRef{{TeamID: "t1", GroupPath: ""}}})
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	if len(st.written) != 0 || len(st.deleted) != 0 {
		t.Errorf("written=%+v deleted=%+v, want no-ops", st.written, st.deleted)
	}
}

// Regression: a non-positive interval must not panic time.NewTicker; Run
// still syncs once and exits on cancel.
func TestOrgTeamSyncRunZeroInterval(t *testing.T) {
	st := &syncStore{}
	syncer := NewOrgTeamSync(st,
		&pathMemberLister{byPath: map[string][]string{"tenant-acme/members": {"u1"}}},
		&fakeTeamGroupLister{groups: []TeamGroupRef{{TeamID: "t1", GroupPath: "tenant-acme/members"}}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		syncer.Run(ctx, 0)
		close(done)
	}()
	cancel()
	<-done
	if len(st.written) != 1 {
		t.Errorf("written = %+v, want the initial sync to have run", st.written)
	}
}
