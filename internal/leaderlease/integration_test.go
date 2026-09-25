//go:build integration

package leaderlease

import (
	"context"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/7K-Inari/inari-server/internal/db"
)

// setupPG starts a Postgres container and returns its connection URL.
func setupPG(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	pg, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("inari"),
		postgres.WithUsername("inari"),
		postgres.WithPassword("inari"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2)),
	)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	t.Cleanup(func() { _ = pg.Terminate(ctx) })
	url, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	database, err := db.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return url
}

// newLeaser connects an independent pool — one per simulated process.
func newLeaser(t *testing.T, url, holder string, ttl time.Duration) Leaser {
	t.Helper()
	database, err := db.Connect(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	return New(database, Config{
		Holder:        holder,
		TTL:           ttl,
		RenewInterval: ttl / 5,
		AcquireRetry:  50 * time.Millisecond,
	})
}

func TestTwoProcessContention(t *testing.T) {
	url := setupPG(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const ttl = time.Second

	la := newLeaser(t, url, "replica-a", ttl)
	lb := newLeaser(t, url, "replica-b", ttl)

	leaseA, err := la.Acquire(ctx, "loop-a")
	if err != nil {
		t.Fatalf("replica A acquire: %v", err)
	}

	// B must not acquire while A holds the lease.
	bCtx, bCancel := context.WithTimeout(ctx, 3*ttl)
	defer bCancel()
	if _, err := lb.Acquire(bCtx, "loop-a"); err == nil {
		t.Fatal("replica B acquired while A held the lease")
	}

	// Voluntary release hands leadership to B promptly.
	if err := leaseA.Release(ctx); err != nil {
		t.Fatalf("replica A release: %v", err)
	}
	leaseB, err := lb.Acquire(ctx, "loop-a")
	if err != nil {
		t.Fatalf("replica B acquire after release: %v", err)
	}
	defer func() { _ = leaseB.Release(context.Background()) }()
}

// TestFailoverOnRenewalStop simulates pod death: the
// holder's lease is acquired with a cancellable context that is then
// cancelled (renewal goroutine exits, no Release), and the peer must take
// over within ~TTL.
func TestFailoverOnRenewalStop(t *testing.T) {
	url := setupPG(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const ttl = time.Second

	la := newLeaser(t, url, "replica-a", ttl)
	lb := newLeaser(t, url, "replica-b", ttl)

	holderCtx, holderCancel := context.WithCancel(context.Background())
	if _, err := la.Acquire(holderCtx, "loop-a"); err != nil {
		t.Fatalf("replica A acquire: %v", err)
	}
	start := time.Now()
	holderCancel() // pod death: renewals stop, row expires at acquired+TTL

	leaseB, err := lb.Acquire(ctx, "loop-a")
	if err != nil {
		t.Fatalf("replica B acquire after failover: %v", err)
	}
	defer func() { _ = leaseB.Release(context.Background()) }()
	if took := time.Since(start); took > 3*ttl {
		t.Fatalf("failover took %v, want within ~%v", took, 3*ttl)
	}
}

func TestRenewKeepsPeerOut(t *testing.T) {
	url := setupPG(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const ttl = time.Second

	la := newLeaser(t, url, "replica-a", ttl)
	lb := newLeaser(t, url, "replica-b", ttl)

	leaseA, err := la.Acquire(ctx, "loop-a")
	if err != nil {
		t.Fatalf("replica A acquire: %v", err)
	}
	defer func() { _ = leaseA.Release(context.Background()) }()

	// Several TTLs pass with A renewing: B must still be locked out.
	bCtx, bCancel := context.WithTimeout(ctx, 3*ttl)
	defer bCancel()
	if _, err := lb.Acquire(bCtx, "loop-a"); err == nil {
		t.Fatal("replica B acquired despite A renewing")
	}
}
