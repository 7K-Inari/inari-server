//go:build integration

package authz

import (
	"context"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/7K-Inari/inari-server/internal/cache"
)

// End-to-end fail-open proof: CachedAuthorizer + InvalidatingStore over a
// real Redis. Traffic is served and invalidated while Redis is up; after the
// container is killed, Checks and writes must still succeed (degrading to
// direct FGA calls) — never fail because the cache is down.
func TestCachedAuthorizerRedisOutageFailsOpen(t *testing.T) {
	ctx := context.Background()
	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "redis:7-alpine",
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForLog("Ready to accept connections"),
		},
		Started: true,
	})
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}

	endpoint, err := ctr.Endpoint(ctx, "")
	if err != nil {
		t.Fatalf("endpoint: %v", err)
	}
	c, err := cache.NewRedis("redis://" + endpoint + "/0")
	if err != nil {
		t.Fatalf("NewRedis: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(ctx) })

	store := newCountingStore()
	store.setAllowed("user:u1", RelationViewer, "organization:o1", true)
	inv := NewInvalidatingStore(store, c, "redis")
	a := NewCachedAuthorizer(NewAuthorizer(store), c, "redis", time.Minute)

	// Healthy path: first Check populates, second is served from Redis.
	for i := 0; i < 2; i++ {
		ok, err := a.Check(ctx, "user:u1", RelationViewer, "organization:o1")
		if err != nil || !ok {
			t.Fatalf("Check %d (redis up) = %v,%v, want true,nil", i, ok, err)
		}
	}
	if n := store.checkCount(); n != 1 {
		t.Fatalf("store checks = %d, want 1 (second check served from redis)", n)
	}

	// Invalidation over redis: a tuple write must make a revocation visible.
	store.setAllowed("user:u1", RelationViewer, "organization:o1", false)
	if err := inv.DeleteTuples(ctx, []Tuple{{User: "user:u1", Relation: RelationViewer, Object: "organization:o1"}}); err != nil {
		t.Fatalf("DeleteTuples: %v", err)
	}
	ok, err := a.Check(ctx, "user:u1", RelationViewer, "organization:o1")
	if err != nil || ok {
		t.Fatalf("Check after revocation = %v,%v, want false,nil", ok, err)
	}

	// Kill Redis mid-traffic: every Check and write must still succeed.
	if err := ctr.Terminate(ctx); err != nil {
		t.Fatalf("terminate redis: %v", err)
	}
	store.setAllowed("user:u1", RelationViewer, "organization:o1", true)
	before := store.checkCount()
	for i := 0; i < 3; i++ {
		ok, err := a.Check(ctx, "user:u1", RelationViewer, "organization:o1")
		if err != nil || !ok {
			t.Fatalf("Check %d (redis down) = %v,%v, want true,nil (fail-open)", i, ok, err)
		}
	}
	if n := store.checkCount(); n != before+3 {
		t.Fatalf("store checks = %d, want %d (every check passes through while redis is down)", n, before+3)
	}
	if err := inv.WriteTuples(ctx, []Tuple{{User: "user:u1", Relation: RelationViewer, Object: "organization:o1"}}); err != nil {
		t.Fatalf("WriteTuples (redis down): %v (invalidation bump must be fail-open)", err)
	}
}
