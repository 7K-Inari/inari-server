package planlimits

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCachedProviderCachesSuccessfulReadsAndClones(t *testing.T) {
	var calls atomic.Int32
	provider := NewCachedProvider(providerFunc(func(context.Context, string) (Limits, error) {
		calls.Add(1)
		one := int64(1)
		return Limits{MaxClusters: &one, FeatureGates: map[string]bool{GateApprovals: true}}, nil
	}), time.Minute)
	first, err := provider.PlanLimits(context.Background(), "org:kc-1")
	if err != nil {
		t.Fatal(err)
	}
	if first.MaxClusters == nil || first.FeatureGates == nil {
		t.Fatalf("provider document was not returned: %+v", first)
	}
	*first.MaxClusters = 99
	first.FeatureGates[GateApprovals] = false
	second, err := provider.PlanLimits(context.Background(), "org:kc-1")
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || *second.MaxClusters != 1 || !second.FeatureGates[GateApprovals] {
		t.Fatalf("cached value was shared or provider reread: calls=%d limits=%+v", calls.Load(), second)
	}
}

func TestCachedProviderExpiresAndDoesNotCacheFailures(t *testing.T) {
	var calls atomic.Int32
	provider := NewCachedProvider(providerFunc(func(context.Context, string) (Limits, error) {
		call := calls.Add(1)
		if call == 2 {
			return Limits{}, errors.New("temporary")
		}
		return Limits{AllFeatures: true}, nil
	}), 5*time.Millisecond)
	if _, err := provider.PlanLimits(context.Background(), "org:kc-1"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if _, err := provider.PlanLimits(context.Background(), "org:kc-1"); err == nil {
		t.Fatal("expired provider failure was hidden")
	}
	if _, err := provider.PlanLimits(context.Background(), "org:kc-1"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatalf("calls = %d, want 3", calls.Load())
	}
}

func TestCachedProviderCoalescesConcurrentReads(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	var startedOnce sync.Once
	provider := NewCachedProvider(providerFunc(func(context.Context, string) (Limits, error) {
		calls.Add(1)
		startedOnce.Do(func() { close(started) })
		<-release
		return Limits{AllFeatures: true}, nil
	}), time.Minute)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = provider.PlanLimits(context.Background(), "org:kc-1")
	}()
	<-started
	go func() {
		defer wg.Done()
		_, _ = provider.PlanLimits(context.Background(), "org:kc-1")
	}()
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("concurrent provider calls = %d, want 1", calls.Load())
	}
}
