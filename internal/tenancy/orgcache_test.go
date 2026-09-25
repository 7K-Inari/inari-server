package tenancy

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/cache"
	"github.com/7K-Inari/inari-server/internal/types"
)

// errCache fails every operation (simulates a Redis outage).
type errCache struct{ cache.Cache }

var errCacheDown = errors.New("cache: connection refused")

func (errCache) Get(context.Context, string) (string, bool, error) {
	return "", false, errCacheDown
}
func (errCache) Set(context.Context, string, string, time.Duration) error { return errCacheDown }
func (errCache) Delete(context.Context, string) error                     { return errCacheDown }
func (errCache) Increment(context.Context, string) (int64, error)         { return 0, errCacheDown }

func org(slug string) *types.Organization {
	return &types.Organization{ID: "org:" + slug, Slug: slug, DisplayName: slug, Status: types.OrgStatusActive}
}

func TestOrgCacheHitAvoidsFetch(t *testing.T) {
	oc := NewOrgCache(cache.NewMemory(100), "memory", time.Minute)
	var fetches atomic.Int64
	fetch := func(context.Context) (*types.Organization, error) {
		fetches.Add(1)
		return org("acme"), nil
	}
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		o, err := oc.Lookup(ctx, "acme", fetch)
		if err != nil || o.Slug != "acme" {
			t.Fatalf("Lookup %d = %v,%v", i, o, err)
		}
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("fetches = %d, want 1 (cache hit)", n)
	}
}

func TestOrgCacheNotFoundNeverCached(t *testing.T) {
	oc := NewOrgCache(cache.NewMemory(100), "memory", time.Minute)
	var fetches atomic.Int64
	fetch := func(context.Context) (*types.Organization, error) {
		fetches.Add(1)
		return nil, ErrOrgNotFound
	}
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		if _, err := oc.Lookup(ctx, "ghost", fetch); err == nil {
			t.Fatalf("Lookup %d: want ErrOrgNotFound", i)
		}
	}
	if n := fetches.Load(); n != 2 {
		t.Fatalf("fetches = %d, want 2 (negative results must not be cached)", n)
	}
}

func TestOrgCacheInvalidation(t *testing.T) {
	oc := NewOrgCache(cache.NewMemory(100), "memory", time.Minute)
	var fetches atomic.Int64
	current := org("acme")
	fetch := func(context.Context) (*types.Organization, error) {
		fetches.Add(1)
		return current, nil
	}
	ctx := context.Background()

	if _, err := oc.Lookup(ctx, "acme", fetch); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	current = &types.Organization{ID: "org:acme", Slug: "acme", DisplayName: "renamed", Status: types.OrgStatusActive}
	oc.Invalidate(ctx, "acme")
	o, err := oc.Lookup(ctx, "acme", fetch)
	if err != nil || o.DisplayName != "renamed" {
		t.Fatalf("Lookup after Invalidate = %v,%v, want renamed org", o, err)
	}
	if n := fetches.Load(); n != 2 {
		t.Fatalf("fetches = %d, want 2", n)
	}
}

func TestOrgCacheTTLExpiry(t *testing.T) {
	oc := NewOrgCache(cache.NewMemory(100), "memory", 30*time.Millisecond)
	var fetches atomic.Int64
	fetch := func(context.Context) (*types.Organization, error) {
		fetches.Add(1)
		return org("acme"), nil
	}
	ctx := context.Background()

	_, _ = oc.Lookup(ctx, "acme", fetch)
	time.Sleep(60 * time.Millisecond)
	_, _ = oc.Lookup(ctx, "acme", fetch)
	if n := fetches.Load(); n != 2 {
		t.Fatalf("fetches = %d, want 2 (TTL expired)", n)
	}
}

func TestOrgCacheFailOpenOnOutage(t *testing.T) {
	oc := NewOrgCache(errCache{}, "redis", time.Minute)
	var fetches atomic.Int64
	fetch := func(context.Context) (*types.Organization, error) {
		fetches.Add(1)
		return org("acme"), nil
	}
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		o, err := oc.Lookup(ctx, "acme", fetch)
		if err != nil || o.Slug != "acme" {
			t.Fatalf("Lookup %d with cache down = %v,%v, want org,nil", i, o, err)
		}
	}
	if n := fetches.Load(); n != 3 {
		t.Fatalf("fetches = %d, want 3 (no caching while cache is down)", n)
	}
	oc.Invalidate(ctx, "acme") // must not panic or block
}

func TestOrgCacheCorruptEntryFallsThrough(t *testing.T) {
	c := cache.NewMemory(100)
	oc := NewOrgCache(c, "memory", time.Minute)
	ctx := context.Background()

	// A corrupt entry (e.g. written by an older schema) must not be served:
	// Lookup falls through to fetch and overwrites it.
	if err := c.Set(ctx, "inari:tenancy:org:acme", "{not json", time.Minute); err != nil {
		t.Fatal(err)
	}
	var fetches atomic.Int64
	fetch := func(context.Context) (*types.Organization, error) {
		fetches.Add(1)
		return org("acme"), nil
	}
	o, err := oc.Lookup(ctx, "acme", fetch)
	if err != nil || o.Slug != "acme" {
		t.Fatalf("Lookup with corrupt entry = %v,%v, want fetched org", o, err)
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("fetches = %d, want 1", n)
	}
	// The corrupt entry was overwritten: next lookup is a clean hit.
	if _, err := oc.Lookup(ctx, "acme", fetch); err != nil {
		t.Fatalf("Lookup after repair: %v", err)
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("fetches = %d, want 1 (entry repaired, served from cache)", n)
	}
}

func TestOrgCacheConcurrent(t *testing.T) {
	oc := NewOrgCache(cache.NewMemory(1000), "memory", time.Minute)
	fetch := func(context.Context) (*types.Organization, error) {
		return org("acme"), nil
	}
	ctx := context.Background()

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				if _, err := oc.Lookup(ctx, "acme", fetch); err != nil {
					t.Errorf("Lookup: %v", err)
				}
				if i%10 == 0 {
					oc.Invalidate(ctx, "acme")
				}
			}
		}()
	}
	wg.Wait()
}
