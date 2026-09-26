package authz

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/cache"
)

type countingStore struct {
	mu        sync.Mutex
	allowed   map[string]bool
	checks    int
	writes    int
	deletes   int
	listCalls int
}

func newCountingStore() *countingStore { return &countingStore{allowed: map[string]bool{}} }

func checkKey(user, relation, object string) string {
	return user + "|" + relation + "|" + object
}

func (f *countingStore) Check(_ context.Context, user, relation, object string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks++
	return f.allowed[checkKey(user, relation, object)], nil
}

func (f *countingStore) ListObjects(context.Context, string, string, string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls++
	return []string{"organization:o1"}, nil
}

func (f *countingStore) ReadTuples(context.Context, string, string) ([]Tuple, error) {
	return nil, nil
}

func (f *countingStore) WriteTuples(context.Context, []Tuple) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes++
	return nil
}

func (f *countingStore) DeleteTuples(context.Context, []Tuple) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes++
	return nil
}

func (f *countingStore) setAllowed(user, relation, object string, allowed bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allowed[checkKey(user, relation, object)] = allowed
}

func (f *countingStore) checkCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.checks
}

// errCache fails every operation (simulates a Redis outage).
type errCache struct{ cache.Cache }

var errCacheDown = errors.New("cache: connection refused")

func (errCache) Get(context.Context, string) (string, bool, error) {
	return "", false, errCacheDown
}
func (errCache) Set(context.Context, string, string, time.Duration) error { return errCacheDown }
func (errCache) Delete(context.Context, string) error                     { return errCacheDown }
func (errCache) Increment(context.Context, string) (int64, error)         { return 0, errCacheDown }

func newPEP(s Store, c cache.Cache) Authorizer {
	return NewCachedAuthorizer(NewAuthorizer(s), c, "memory", time.Minute)
}

func TestCachedAuthorizerCachesCheckResults(t *testing.T) {
	store := newCountingStore()
	store.setAllowed("user:u1", RelationViewer, "organization:o1", true)
	a := newPEP(store, cache.NewMemory(100))
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		ok, err := a.Check(ctx, "user:u1", RelationViewer, "organization:o1")
		if err != nil || !ok {
			t.Fatalf("Check %d = %v,%v, want true,nil", i, ok, err)
		}
	}
	if n := store.checkCount(); n != 1 {
		t.Fatalf("store checks = %d, want 1 (subsequent hits served from cache)", n)
	}
}

func TestCachedAuthorizerCachesDenies(t *testing.T) {
	store := newCountingStore() // nothing allowed
	a := newPEP(store, cache.NewMemory(100))
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		ok, err := a.Check(ctx, "user:u1", RelationAdmin, "organization:o1")
		if err != nil || ok {
			t.Fatalf("Check %d = %v,%v, want false,nil", i, ok, err)
		}
	}
	if n := store.checkCount(); n != 1 {
		t.Fatalf("store checks = %d, want 1 (deny must be cached too)", n)
	}
}

func TestCachedAuthorizerKeysByUserRelationObject(t *testing.T) {
	store := newCountingStore()
	store.setAllowed("user:u1", RelationViewer, "organization:o1", true)
	a := newPEP(store, cache.NewMemory(100))
	ctx := context.Background()

	_, _ = a.Check(ctx, "user:u1", RelationViewer, "organization:o1")
	_, _ = a.Check(ctx, "user:u2", RelationViewer, "organization:o1")
	_, _ = a.Check(ctx, "user:u1", RelationAdmin, "organization:o1")
	_, _ = a.Check(ctx, "user:u1", RelationViewer, "organization:o2")
	if n := store.checkCount(); n != 4 {
		t.Fatalf("store checks = %d, want 4 (distinct key tuples)", n)
	}
}

func TestCachedAuthorizerInvalidatedByTupleWrite(t *testing.T) {
	store := newCountingStore()
	// Authorizer and writer share the same cache instance, as in main.go.
	c := cache.NewMemory(100)
	inv := NewInvalidatingStore(store, c, "memory")
	a := NewCachedAuthorizer(NewAuthorizer(store), c, "memory", time.Minute)
	ctx := context.Background()

	ok, err := a.Check(ctx, "user:u1", RelationViewer, "organization:o1")
	if err != nil || ok {
		t.Fatalf("Check before grant = %v,%v, want false,nil", ok, err)
	}
	store.setAllowed("user:u1", RelationViewer, "organization:o1", true)
	if err := inv.WriteTuples(ctx, []Tuple{{User: "user:u1", Relation: RelationViewer, Object: "organization:o1"}}); err != nil {
		t.Fatalf("WriteTuples: %v", err)
	}
	ok, err = a.Check(ctx, "user:u1", RelationViewer, "organization:o1")
	if err != nil || !ok {
		t.Fatalf("Check after write invalidation = %v,%v, want true,nil", ok, err)
	}

	if err := inv.DeleteTuples(ctx, []Tuple{{User: "user:u1", Relation: RelationViewer, Object: "organization:o1"}}); err != nil {
		t.Fatalf("DeleteTuples: %v", err)
	}
	store.setAllowed("user:u1", RelationViewer, "organization:o1", false)
	ok, err = a.Check(ctx, "user:u1", RelationViewer, "organization:o1")
	if err != nil || ok {
		t.Fatalf("Check after delete invalidation = %v,%v, want false,nil", ok, err)
	}
}

func TestCachedAuthorizerFailOpenOnCacheOutage(t *testing.T) {
	store := newCountingStore()
	store.setAllowed("user:u1", RelationViewer, "organization:o1", true)
	a := newPEP(store, errCache{})
	ctx := context.Background()

	// Every request must still be served by the underlying store.
	for i := 0; i < 3; i++ {
		ok, err := a.Check(ctx, "user:u1", RelationViewer, "organization:o1")
		if err != nil || !ok {
			t.Fatalf("Check %d with cache down = %v,%v, want true,nil", i, ok, err)
		}
	}
	if n := store.checkCount(); n != 3 {
		t.Fatalf("store checks = %d, want 3 (no caching while cache is down)", n)
	}

	// Writes must also succeed and not fail on the invalidation bump.
	inv := NewInvalidatingStore(store, errCache{}, "redis")
	if err := inv.WriteTuples(ctx, []Tuple{{}}); err != nil {
		t.Fatalf("WriteTuples with cache down: %v", err)
	}
	if err := inv.DeleteTuples(ctx, []Tuple{{}}); err != nil {
		t.Fatalf("DeleteTuples with cache down: %v", err)
	}
}

func TestCachedAuthorizerTTLExpiry(t *testing.T) {
	store := newCountingStore()
	c := cache.NewMemory(100)
	a := NewCachedAuthorizer(NewAuthorizer(store), c, "memory", 30*time.Millisecond)
	ctx := context.Background()

	_, _ = a.Check(ctx, "user:u1", RelationViewer, "organization:o1")
	store.setAllowed("user:u1", RelationViewer, "organization:o1", true)
	time.Sleep(60 * time.Millisecond)
	ok, err := a.Check(ctx, "user:u1", RelationViewer, "organization:o1")
	if err != nil || !ok {
		t.Fatalf("Check after TTL expiry = %v,%v, want true,nil", ok, err)
	}
}

func TestCachedAuthorizerListObjectsNotCached(t *testing.T) {
	store := newCountingStore()
	a := newPEP(store, cache.NewMemory(100))
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		objs, err := a.ListObjects(ctx, "user:u1", RelationViewer, TypeOrganization)
		if err != nil || len(objs) != 1 {
			t.Fatalf("ListObjects %d = %v,%v", i, objs, err)
		}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.listCalls != 3 {
		t.Fatalf("ListObjects calls = %d, want 3 (never cached)", store.listCalls)
	}
}

func TestCachedAuthorizerConcurrentChecksAndWrites(t *testing.T) {
	store := newCountingStore()
	c := cache.NewMemory(1000)
	inv := NewInvalidatingStore(store, c, "memory")
	a := NewCachedAuthorizer(NewAuthorizer(store), c, "memory", time.Minute)
	ctx := context.Background()

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(2)
		go func(g int) { // reader
			defer wg.Done()
			for i := 0; i < 100; i++ {
				if _, err := a.Check(ctx, fmt.Sprintf("user:u%d", g), RelationViewer, "organization:o1"); err != nil {
					t.Errorf("Check: %v", err)
				}
			}
		}(g)
		go func(g int) { // writer (invalidates)
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if err := inv.WriteTuples(ctx, []Tuple{{User: fmt.Sprintf("user:u%d", g), Relation: RelationViewer, Object: "organization:o1"}}); err != nil {
					t.Errorf("WriteTuples: %v", err)
				}
			}
		}(g)
	}
	wg.Wait()

	// After all writes have completed, a grant must be visible immediately
	// (generation bumped), not after TTL.
	store.setAllowed("user:u9", RelationViewer, "organization:o1", true)
	if err := inv.WriteTuples(ctx, []Tuple{{User: "user:u9", Relation: RelationViewer, Object: "organization:o1"}}); err != nil {
		t.Fatalf("WriteTuples: %v", err)
	}
	ok, err := a.Check(ctx, "user:u9", RelationViewer, "organization:o1")
	if err != nil || !ok {
		t.Fatalf("Check after final write = %v,%v, want true,nil", ok, err)
	}
}
