//go:build integration

package cache

import (
	"context"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestRedisConformance(t *testing.T) {
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "redis:7-alpine",
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForLog("Ready to accept connections"),
	}
	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req, Started: true,
	})
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(ctx) })

	endpoint, err := ctr.Endpoint(ctx, "")
	if err != nil {
		t.Fatalf("endpoint: %v", err)
	}
	c, err := NewRedis("redis://" + endpoint + "/0")
	if err != nil {
		t.Fatalf("NewRedis: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(ctx) })

	conformance(t, c)

	// TTL expiry round-trips through redis.
	if err := c.Set(ctx, "ttl", "v", 50*time.Millisecond); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, ok, _ := c.Get(ctx, "ttl"); !ok {
		t.Fatal("Get before expiry: want hit")
	}
	time.Sleep(100 * time.Millisecond)
	if _, ok, err := c.Get(ctx, "ttl"); err != nil || ok {
		t.Fatalf("Get after expiry = ok=%v err=%v, want miss", ok, err)
	}
}
