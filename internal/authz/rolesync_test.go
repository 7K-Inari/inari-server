package authz

import (
	"context"
	"fmt"
	"testing"
)

// recordingStore is an in-memory Store for reconciler tests.
type recordingStore struct {
	tuples  map[string]bool // user|relation|object
	readErr map[string]error
}

func newRecordingStore() *recordingStore {
	return &recordingStore{tuples: map[string]bool{}, readErr: map[string]error{}}
}

func key(u, r, o string) string { return u + "|" + r + "|" + o }

func (s *recordingStore) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}
func (s *recordingStore) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}
func (s *recordingStore) ReadTuples(_ context.Context, object, relation string) ([]Tuple, error) {
	if err, ok := s.readErr[relation]; ok {
		return nil, err
	}
	var out []Tuple
	for k := range s.tuples {
		parts := split3(k)
		if parts[2] == object && parts[1] == relation {
			out = append(out, Tuple{User: parts[0], Relation: parts[1], Object: parts[2]})
		}
	}
	return out, nil
}
func split3(k string) [3]string {
	var out [3]string
	idx := 0
	start := 0
	for i := 0; i < len(k) && idx < 2; i++ {
		if k[i] == '|' {
			out[idx] = k[start:i]
			idx++
			start = i + 1
		}
	}
	out[2] = k[start:]
	return out
}
func (s *recordingStore) WriteTuples(_ context.Context, tuples []Tuple) error {
	for _, t := range tuples {
		s.tuples[key(t.User, t.Relation, t.Object)] = true
	}
	return nil
}
func (s *recordingStore) DeleteTuples(_ context.Context, tuples []Tuple) error {
	for _, t := range tuples {
		delete(s.tuples, key(t.User, t.Relation, t.Object))
	}
	return nil
}

func refs(refs ...TeamGroupRef) TeamGroupLister {
	return TeamGroupListerFunc(func(context.Context) ([]TeamGroupRef, error) { return refs, nil })
}

func TestOrgRoleSyncPopulatesAndConverges(t *testing.T) {
	store := newRecordingStore()
	// Drift: a stale tuple for a team that no longer grants the permission,
	// and a legacy-relation tuple from before the model swap.
	store.tuples[key("team:t-old#member", "tenant_read", "organization:1")] = true
	store.tuples[key("team:t1#member", "admin", "organization:1")] = true

	s := NewOrgRoleSync(store, refs(
		TeamGroupRef{TeamID: "t1", OrgID: "org:1", RoleID: "r1", Permissions: []string{"tenant.read", "tenant.admin"}, GroupPath: "tenant-acme/admins"},
		TeamGroupRef{TeamID: "t2", OrgID: "org:1", RoleID: "r2", Permissions: []string{"tenant.read"}, GroupPath: "tenant-acme/devs"},
	))
	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	// Desired tuples present.
	for _, want := range []string{
		key("team:t1#member", "tenant_read", "organization:1"),
		key("team:t1#member", "tenant_admin", "organization:1"),
		key("team:t2#member", "tenant_read", "organization:1"),
	} {
		if !store.tuples[want] {
			t.Errorf("missing desired tuple %s", want)
		}
	}
	// Stale and legacy tuples retracted.
	for _, gone := range []string{
		key("team:t-old#member", "tenant_read", "organization:1"),
		key("team:t1#member", "admin", "organization:1"),
	} {
		if store.tuples[gone] {
			t.Errorf("tuple %s should have been retracted", gone)
		}
	}
	// Idempotent: second pass converges to a no-op.
	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatalf("second SyncOnce: %v", err)
	}
	if len(store.tuples) != 3 {
		t.Fatalf("tuples after second pass = %v, want 3", store.tuples)
	}
}

func TestOrgRoleSyncToleratesLegacyRelationNotFound(t *testing.T) {
	store := newRecordingStore()
	for _, rel := range legacyOrgRelations {
		store.readErr[rel] = fmt.Errorf("read: relation %q not found in model", rel)
	}
	s := NewOrgRoleSync(store, refs(
		TeamGroupRef{TeamID: "t1", OrgID: "org:1", RoleID: "r1", Permissions: []string{"tenant.read"}, GroupPath: "p"},
	))
	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce with relation-not-found legacy reads must succeed: %v", err)
	}
	if !store.tuples[key("team:t1#member", "tenant_read", "organization:1")] {
		t.Fatal("desired tuple not written")
	}
}

func TestOrgRoleSyncSkipsUnknownPermissionSlugs(t *testing.T) {
	store := newRecordingStore()
	s := NewOrgRoleSync(store, refs(
		TeamGroupRef{TeamID: "t1", OrgID: "org:1", RoleID: "r1", Permissions: []string{"tenant.read", "retired.slug"}, GroupPath: "p"},
	))
	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	if len(store.tuples) != 1 || !store.tuples[key("team:t1#member", "tenant_read", "organization:1")] {
		t.Fatalf("tuples = %v, want only tenant_read", store.tuples)
	}
}
