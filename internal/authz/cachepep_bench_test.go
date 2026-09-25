package authz

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/cache"
)

// latencyStore simulates an OpenFGA round trip (spike m1-openfga-performance
// measured single-digit-ms Check latency) to make the cache win measurable.
type latencyStore struct {
	latency time.Duration
}

func (s *latencyStore) Check(context.Context, string, string, string) (bool, error) {
	time.Sleep(s.latency)
	return true, nil
}
func (s *latencyStore) ListObjects(context.Context, string, string, string) ([]string, error) {
	time.Sleep(s.latency)
	return nil, nil
}
func (s *latencyStore) ReadTuples(context.Context, string, string) ([]Tuple, error) {
	return nil, nil
}
func (s *latencyStore) WriteTuples(context.Context, []Tuple) error  { return nil }
func (s *latencyStore) DeleteTuples(context.Context, []Tuple) error { return nil }

// BenchmarkPEPCheck compares a single authorizeOrg-style Check with and
// without the PEP cache.
func BenchmarkPEPCheck(b *testing.B) {
	const fgaLatency = 5 * time.Millisecond
	ctx := context.Background()
	for _, cached := range []bool{false, true} {
		name := "uncached"
		if cached {
			name = "cached"
		}
		b.Run(name, func(b *testing.B) {
			var a Authorizer = NewAuthorizer(&latencyStore{latency: fgaLatency})
			if cached {
				a = NewCachedAuthorizer(a, cache.NewMemory(10000), "memory", 2*time.Second)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := a.Check(ctx, "user:u1", RelationViewer, "organization:o1"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkMePermissions simulates the GET /api/v1/me/permissions hot path
// (internal/tenancy/me.go): per org in the token, 1 slug->org lookup plus up
// to 4 sequential role-ladder Checks (early exit on the first grant). Here
// every user is a viewer, so each org costs the full 4 Checks + 1 org
// lookup, each paying the simulated round-trip latency when uncached.
func BenchmarkMePermissions(b *testing.B) {
	const (
		fgaLatency = 5 * time.Millisecond
		dbLatency  = time.Millisecond
		orgCount   = 5
	)
	ctx := context.Background()
	roles := []string{RelationAdmin, RelationPlatformEngineer, RelationDeveloper, RelationViewer}

	for _, cached := range []bool{false, true} {
		name := "uncached"
		if cached {
			name = "cached"
		}
		b.Run(name, func(b *testing.B) {
			var a Authorizer = NewAuthorizer(&latencyStore{latency: fgaLatency})
			var orgLookup = func(context.Context, string) error {
				time.Sleep(dbLatency)
				return nil
			}
			if cached {
				c := cache.NewMemory(10000)
				a = NewCachedAuthorizer(a, c, "memory", 2*time.Second)
				hits := cache.NewMemory(10000)
				orgLookup = func(ctx context.Context, slug string) error {
					if _, hit, _ := hits.Get(ctx, "org:"+slug); hit {
						return nil
					}
					time.Sleep(dbLatency)
					_ = hits.Set(ctx, "org:"+slug, "1", 10*time.Second)
					return nil
				}
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for o := 0; o < orgCount; o++ {
					slug := fmt.Sprintf("org-%d", o)
					if err := orgLookup(ctx, slug); err != nil {
						b.Fatal(err)
					}
					obj := "organization:" + slug
					for _, rel := range roles {
						ok, err := a.Check(ctx, "user:u1", rel, obj)
						if err != nil {
							b.Fatal(err)
						}
						if ok {
							break
						}
					}
				}
			}
		})
	}
}
