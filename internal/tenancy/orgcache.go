package tenancy

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/7K-Inari/inari-server/internal/cache"
	"github.com/7K-Inari/inari-server/internal/metrics"
	"github.com/7K-Inari/inari-server/internal/types"
)

// OrgCache caches the tenant slug -> organization row (JSON) with a short
// TTL (INARI_CACHE_TENANT_TTL). It backs Service.GetTenant, the single
// funnel every module's authorizeOrg calls per request, collapsing the
// Postgres lookup on the hot path. Only positive results are cached: an
// ErrOrgNotFound must never be served stale (org creation is immediately
// visible).
//
// Fail-open contract: any cache error degrades to a direct store fetch,
// logged (sampled) and metered. Multi-replica note: with the memory backend
// invalidation is process-local and cross-replica staleness is bounded by
// the TTL; the redis backend shares invalidation across replicas.
type OrgCache struct {
	cache    cache.Cache
	backend  string
	ttl      time.Duration
	failures atomic.Int64
}

// NewOrgCache wraps c. backend labels metrics ("memory"|"redis").
func NewOrgCache(c cache.Cache, backend string, ttl time.Duration) *OrgCache {
	return &OrgCache{cache: c, backend: backend, ttl: ttl}
}

func orgCacheKey(slug string) string { return "inari:tenancy:org:" + slug }

// Lookup returns the org for slug, serving from cache on hit and populating
// the cache after a successful fetch. Fetch errors (including ErrOrgNotFound)
// propagate and are never cached.
func (o *OrgCache) Lookup(ctx context.Context, slug string, fetch func(context.Context) (*types.Organization, error)) (*types.Organization, error) {
	key := orgCacheKey(slug)
	switch v, hit, err := o.cache.Get(ctx, key); {
	case err != nil:
		o.failOpen(ctx, metrics.OpGet, err)
	case hit:
		metrics.RecordCacheOp(ctx, metrics.CacheTenant, o.backend, metrics.OpGet, metrics.ResultHit)
		var org types.Organization
		if jerr := json.Unmarshal([]byte(v), &org); jerr == nil {
			return &org, nil
		}
		// Corrupt entry: fall through to fetch and overwrite.
	default:
		metrics.RecordCacheOp(ctx, metrics.CacheTenant, o.backend, metrics.OpGet, metrics.ResultMiss)
	}
	org, err := fetch(ctx)
	if err != nil {
		return nil, err
	}
	raw, jerr := json.Marshal(org)
	if jerr == nil {
		if serr := o.cache.Set(ctx, key, string(raw), o.ttl); serr != nil {
			o.failOpen(ctx, metrics.OpSet, serr)
		}
	}
	return org, nil
}

// Invalidate evicts the cached org for slug after a mutation (create,
// display-name update, status change, deletion). Errors are fail-open: TTL
// bounds staleness.
func (o *OrgCache) Invalidate(ctx context.Context, slug string) {
	if err := o.cache.Delete(ctx, orgCacheKey(slug)); err != nil {
		o.failOpen(ctx, metrics.OpDelete, err)
		return
	}
	metrics.RecordInvalidation(ctx, metrics.CacheTenant)
}

// failOpen logs (first failure, then every 100th) and meters a cache error.
func (o *OrgCache) failOpen(ctx context.Context, op string, err error) {
	metrics.RecordCacheOp(ctx, metrics.CacheTenant, o.backend, op, metrics.ResultError)
	if n := o.failures.Add(1); n == 1 || n%100 == 0 {
		slog.Warn("tenancy: org cache error, failing open to Postgres", "op", op, "failures", n, "error", err)
	}
}
