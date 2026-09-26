//go:build integration

package leaderlease

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// QA adversarial: N leasers fire Acquire simultaneously; exactly one must win.
func TestSimultaneousAcquireExactlyOneWinner(t *testing.T) {
	url := setupPG(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	const n = 8
	const ttl = 2 * time.Second

	var wg sync.WaitGroup
	results := make(chan Lease, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l := newLeaser(t, url, fmt.Sprintf("replica-%d", i), ttl)
			lease, err := l.Acquire(ctx, "hot-lease")
			if err == nil {
				results <- lease
			}
		}(i)
	}
	wg.Wait()
	close(results)
	var winners []Lease
	for lease := range results {
		winners = append(winners, lease)
	}
	if len(winners) != 1 {
		t.Fatalf("want exactly 1 winner, got %d", len(winners))
	}
	defer func() { _ = winners[0].Release(context.Background()) }()

	// While the winner renews, no one else can sneak in over several TTLs.
	for i := 0; i < n; i++ {
		l := newLeaser(t, url, fmt.Sprintf("sneak-%d", i), ttl)
		sctx, scancel := context.WithTimeout(ctx, ttl)
		if _, err := l.Acquire(sctx, "hot-lease"); err == nil {
			scancel()
			t.Fatal("second holder acquired while winner renewed")
		}
		scancel()
	}
}

// QA adversarial: winner forfeits (renewals stop via ctx cancel) mid-hold;
// exactly one new winner emerges from a thundering herd.
func TestHerdFailoverSingleWinner(t *testing.T) {
	url := setupPG(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	const ttl = time.Second

	holderCtx, holderCancel := context.WithCancel(context.Background())
	la := newLeaser(t, url, "holder", ttl)
	if _, err := la.Acquire(holderCtx, "herd-lease"); err != nil {
		t.Fatal(err)
	}

	const n = 6
	waiters := make([]Leaser, n)
	for i := range waiters {
		waiters[i] = newLeaser(t, url, fmt.Sprintf("waiter-%d", i), ttl)
	}
	holderCancel() // pod death

	var wg sync.WaitGroup
	results := make(chan Lease, n)
	for _, l := range waiters {
		wg.Add(1)
		go func(l Leaser) {
			defer wg.Done()
			lease, err := l.Acquire(ctx, "herd-lease")
			if err == nil {
				results <- lease
			}
		}(l)
	}
	wg.Wait()
	close(results)
	count := 0
	for lease := range results {
		count++
		defer func() { _ = lease.Release(context.Background()) }()
	}
	if count != 1 {
		t.Fatalf("failover herd: want 1 winner, got %d", count)
	}
}
