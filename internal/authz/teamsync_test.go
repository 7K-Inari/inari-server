package authz

import (
	"context"
	"errors"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

// pathUserLister fakes Keycloak group membership (full profiles) keyed by
// group path.
type pathUserLister struct {
	byPath map[string][]*types.User
	errs   map[string]error
	calls  map[string]int
}

func (f *pathUserLister) ListGroupMemberUsers(_ context.Context, path string) ([]*types.User, error) {
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[path]++
	if err := f.errs[path]; err != nil {
		return nil, err
	}
	return f.byPath[path], nil
}

func idUsers(ids ...string) []*types.User {
	out := make([]*types.User, 0, len(ids))
	for _, id := range ids {
		out = append(out, &types.User{ID: id})
	}
	return out
}

type fakeTeamGroupLister struct{ groups []TeamGroupRef }

func (f *fakeTeamGroupLister) ListTeamGroups(context.Context) ([]TeamGroupRef, error) {
	return f.groups, nil
}

type projectedCall struct {
	ref     TeamGroupRef
	members []*types.User
}

// fakeProjector records SyncTeamMembers calls and can fail per group path.
type fakeProjector struct {
	calls []projectedCall
	errs  map[string]error
}

func (f *fakeProjector) SyncTeamMembers(_ context.Context, ref TeamGroupRef, members []*types.User) error {
	f.calls = append(f.calls, projectedCall{ref: ref, members: members})
	return f.errs[ref.GroupPath]
}

func TestOrgTeamSyncWritesNewMembers(t *testing.T) {
	st := &syncStore{}
	syncer := NewOrgTeamSync(st,
		&pathUserLister{byPath: map[string][]*types.User{"tenant-acme/members": idUsers("u1", "u2")}},
		&fakeTeamGroupLister{groups: []TeamGroupRef{{TeamID: "t1", GroupPath: "tenant-acme/members"}}},
		&fakeProjector{})
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
		&pathUserLister{byPath: map[string][]*types.User{"tenant-acme/members": idUsers("u1")}},
		&fakeTeamGroupLister{groups: []TeamGroupRef{{TeamID: "t1", GroupPath: "tenant-acme/members"}}},
		&fakeProjector{})
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
		&pathUserLister{byPath: map[string][]*types.User{
			"tenant-acme/members":    idUsers("u1"),
			"tenant-acme/developers": idUsers("u1", "u2"),
			"tenant-globex/members":  {},
		}},
		&fakeTeamGroupLister{groups: []TeamGroupRef{
			{TeamID: "ta1", GroupPath: "tenant-acme/members"},
			{TeamID: "ta2", GroupPath: "tenant-acme/developers"},
			{TeamID: "tb", GroupPath: "tenant-globex/members"},
		}},
		&fakeProjector{})
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
		&pathUserLister{byPath: map[string][]*types.User{"tenant-acme/members": idUsers("u1")}},
		&fakeTeamGroupLister{groups: []TeamGroupRef{{TeamID: "t1", GroupPath: "tenant-acme/members"}}},
		&fakeProjector{})
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
		&pathUserLister{
			byPath: map[string][]*types.User{"tenant-globex/members": idUsers("u9")},
			errs:   map[string]error{"tenant-acme/members": errors.New("keycloak down")},
		},
		&fakeTeamGroupLister{groups: []TeamGroupRef{
			{TeamID: "ta", GroupPath: "tenant-acme/members"},
			{TeamID: "tb", GroupPath: "tenant-globex/members"},
		}},
		&fakeProjector{})
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
	proj := &fakeProjector{}
	syncer := NewOrgTeamSync(st,
		&pathUserLister{byPath: map[string][]*types.User{}},
		&fakeTeamGroupLister{groups: []TeamGroupRef{{TeamID: "t1", GroupPath: ""}}},
		proj)
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	if len(st.written) != 0 || len(st.deleted) != 0 {
		t.Errorf("written=%+v deleted=%+v, want no-ops", st.written, st.deleted)
	}
	if len(proj.calls) != 0 {
		t.Errorf("projector calls = %+v, want none for skipped group", proj.calls)
	}
}

// Regression: a non-positive interval must not panic time.NewTicker; Run
// still syncs once and exits on cancel.
func TestOrgTeamSyncRunZeroInterval(t *testing.T) {
	st := &syncStore{}
	syncer := NewOrgTeamSync(st,
		&pathUserLister{byPath: map[string][]*types.User{"tenant-acme/members": idUsers("u1")}},
		&fakeTeamGroupLister{groups: []TeamGroupRef{{TeamID: "t1", GroupPath: "tenant-acme/members"}}},
		&fakeProjector{})
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

// The projector receives exactly the Keycloak members of each group, with
// the full team ref (org + role) the DB projection denormalizes.
func TestOrgTeamSyncProjectsMembersToDB(t *testing.T) {
	st := &syncStore{}
	members := []*types.User{
		{ID: "u1", Email: "a@example.com", DisplayName: "A"},
		{ID: "u2", Email: "b@example.com"},
	}
	proj := &fakeProjector{}
	syncer := NewOrgTeamSync(st,
		&pathUserLister{byPath: map[string][]*types.User{"tenant-acme/members": members}},
		&fakeTeamGroupLister{groups: []TeamGroupRef{{
			TeamID: "t1", OrgID: "org:1", RoleID: "r-viewer", GroupPath: "tenant-acme/members",
		}}},
		proj)
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	if len(proj.calls) != 1 {
		t.Fatalf("projector calls = %d, want 1", len(proj.calls))
	}
	call := proj.calls[0]
	if call.ref.TeamID != "t1" || call.ref.OrgID != "org:1" || call.ref.RoleID != "r-viewer" {
		t.Errorf("projected ref = %+v, want t1/org:1/viewer", call.ref)
	}
	if len(call.members) != 2 || call.members[0].ID != "u1" || call.members[1].ID != "u2" {
		t.Errorf("projected members = %+v, want the KC member profiles", call.members)
	}
}

// One Keycloak read per group per tick drives both the FGA tuple diff and
// the DB projection.
func TestOrgTeamSyncSingleKeycloakRead(t *testing.T) {
	st := &syncStore{}
	lister := &pathUserLister{byPath: map[string][]*types.User{"tenant-acme/members": idUsers("u1")}}
	syncer := NewOrgTeamSync(st, lister,
		&fakeTeamGroupLister{groups: []TeamGroupRef{{TeamID: "t1", GroupPath: "tenant-acme/members"}}},
		&fakeProjector{})
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	if got := lister.calls["tenant-acme/members"]; got != 1 {
		t.Errorf("ListGroupMemberUsers calls = %d, want 1", got)
	}
}

// A projection failure is joined into the error and isolates per group, the
// same as a tuple-write failure.
func TestOrgTeamSyncProjectionErrorIsolation(t *testing.T) {
	st := &syncStore{}
	proj := &fakeProjector{errs: map[string]error{"tenant-acme/members": errors.New("db down")}}
	syncer := NewOrgTeamSync(st,
		&pathUserLister{byPath: map[string][]*types.User{
			"tenant-acme/members":   idUsers("u1"),
			"tenant-globex/members": idUsers("u2"),
		}},
		&fakeTeamGroupLister{groups: []TeamGroupRef{
			{TeamID: "ta", GroupPath: "tenant-acme/members"},
			{TeamID: "tb", GroupPath: "tenant-globex/members"},
		}},
		proj)
	if err := syncer.SyncOnce(context.Background()); err == nil {
		t.Fatal("SyncOnce: want joined error for the failing projection")
	}
	if len(st.written) != 2 {
		t.Errorf("written = %+v, want tuple convergence for both groups", st.written)
	}
	if len(proj.calls) != 2 {
		t.Errorf("projector calls = %d, want both groups attempted", len(proj.calls))
	}
}
