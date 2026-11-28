package planlimits

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

type cacheEntry struct {
	limits    Limits
	expiresAt time.Time
}

// CachedProvider caches successful provider reads and coalesces concurrent
// misses per tenant. Failures are never cached or hidden behind stale data.
type CachedProvider struct {
	provider PlanLimitsProvider
	ttl      time.Duration
	now      func() time.Time

	mu      sync.RWMutex
	entries map[string]cacheEntry
	group   singleflight.Group
}

func NewCachedProvider(provider PlanLimitsProvider, ttl time.Duration) *CachedProvider {
	if provider == nil {
		provider = UnlimitedProvider{}
	}
	return &CachedProvider{provider: provider, ttl: ttl, now: time.Now, entries: map[string]cacheEntry{}}
}

func (p *CachedProvider) PlanLimits(ctx context.Context, tenantID string) (Limits, error) {
	if p.ttl <= 0 {
		return p.provider.PlanLimits(ctx, tenantID)
	}
	if limits, ok := p.cached(tenantID); ok {
		return limits, nil
	}
	value, err, _ := p.group.Do(tenantID, func() (any, error) {
		if limits, ok := p.cached(tenantID); ok {
			return limits, nil
		}
		limits, err := p.provider.PlanLimits(ctx, tenantID)
		if err != nil {
			return Limits{}, err
		}
		limits = cloneLimits(limits)
		p.mu.Lock()
		p.entries[tenantID] = cacheEntry{limits: limits, expiresAt: p.now().Add(p.ttl)}
		p.mu.Unlock()
		return limits, nil
	})
	if err != nil {
		return Limits{}, err
	}
	return cloneLimits(value.(Limits)), nil
}

func (p *CachedProvider) cached(tenantID string) (Limits, bool) {
	p.mu.RLock()
	entry, ok := p.entries[tenantID]
	p.mu.RUnlock()
	if !ok || !p.now().Before(entry.expiresAt) {
		return Limits{}, false
	}
	return cloneLimits(entry.limits), true
}
