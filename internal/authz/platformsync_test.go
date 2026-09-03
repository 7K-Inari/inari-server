package authz

import (
	"context"
	"testing"
)

type fakeMemberLister struct{ ids []string }

func (f *fakeMemberLister) ListGroupMembers(context.Context, string) ([]string, error) {
	return f.ids, nil
}

type syncStore struct {
	existing []Tuple
	written  []Tuple
	deleted  []Tuple
}

func (s *syncStore) Check(context.Context, string, string, string) (bool, error) { return false, nil }
func (s *syncStore) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}
func (s *syncStore) ReadTuples(_ context.Context, object, relation string) ([]Tuple, error) {
	var out []Tuple
	for _, t := range s.existing {
		if t.Object == object && t.Relation == relation {
			out = append(out, t)
		}
	}
	return out, nil
}
func (s *syncStore) WriteTuples(_ context.Context, t []Tuple) error {
	s.written = append(s.written, t...)
	return nil
}
func (s *syncStore) DeleteTuples(_ context.Context, t []Tuple) error {
	s.deleted = append(s.deleted, t...)
	return nil
}

func TestPlatformGroupSyncWritesNewMembers(t *testing.T) {
	st := &syncStore{}
	syncer := NewPlatformGroupSync(st, &fakeMemberLister{ids: []string{"u1", "u2"}}, "platform-admins")
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	if len(st.written) != 2 {
		t.Fatalf("written = %+v, want 2", st.written)
	}
	for _, tup := range st.written {
		if tup.Relation != RelationOrgCreator || tup.Object != ObjectPlatform {
			t.Errorf("tuple = %+v, want org_creator on platform:inari", tup)
		}
	}
	if len(st.deleted) != 0 {
		t.Errorf("deleted = %+v, want none", st.deleted)
	}
}

func TestPlatformGroupSyncDeletesRemovedMembers(t *testing.T) {
	st := &syncStore{existing: []Tuple{
		{User: "user:u1", Relation: RelationOrgCreator, Object: ObjectPlatform},
		{User: "user:u2", Relation: RelationOrgCreator, Object: ObjectPlatform},
	}}
	syncer := NewPlatformGroupSync(st, &fakeMemberLister{ids: []string{"u1"}}, "platform-admins")
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

func TestPlatformGroupSyncIdempotent(t *testing.T) {
	st := &syncStore{existing: []Tuple{
		{User: "user:u1", Relation: RelationOrgCreator, Object: ObjectPlatform},
	}}
	syncer := NewPlatformGroupSync(st, &fakeMemberLister{ids: []string{"u1"}}, "platform-admins")
	for i := 0; i < 2; i++ {
		if err := syncer.SyncOnce(context.Background()); err != nil {
			t.Fatalf("SyncOnce: %v", err)
		}
	}
	if len(st.written) != 0 || len(st.deleted) != 0 {
		t.Errorf("written=%+v deleted=%+v, want no-ops", st.written, st.deleted)
	}
}

func TestPlatformGroupSyncEmptyGroupDeletesAll(t *testing.T) {
	st := &syncStore{existing: []Tuple{
		{User: "user:u1", Relation: RelationOrgCreator, Object: ObjectPlatform},
		// A superuser tuple is a different relation: never touched.
		{User: "user:root", Relation: RelationSuperuser, Object: ObjectPlatform},
	}}
	syncer := NewPlatformGroupSync(st, &fakeMemberLister{}, "platform-admins")
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	if len(st.deleted) != 1 || st.deleted[0].Relation != RelationOrgCreator {
		t.Errorf("deleted = %+v, want only the org_creator tuple", st.deleted)
	}
}

// Regression: a non-positive interval (e.g. INARI_PLATFORM_GROUP_SYNC_INTERVAL=0s)
// must not panic time.NewTicker; Run still syncs once and exits on cancel.
func TestPlatformGroupSyncRunZeroInterval(t *testing.T) {
	st := &syncStore{}
	syncer := NewPlatformGroupSync(st, &fakeMemberLister{ids: []string{"u1"}}, "platform-admins")
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
