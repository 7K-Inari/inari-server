package authz

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/7K-Inari/inari-server/internal/cache"
	"github.com/7K-Inari/inari-server/internal/metrics"
)

// pepGenerationKey is the shared invalidation counter for the PEP cache.
// CachedAuthorizer stamps every entry with the current generation;
// InvalidatingStore bumps it after every successful tuple write/delete, so
// stale entries from earlier generations are never read again (they expire
// via TTL without needing DEL scans).
const pepGenerationKey = "inari:fga:pep:gen"

// CachedAuthorizer decorates an Authorizer with the PEP cache mandated by
// spike m1-openfga-performance: Check results are cached with a short TTL
// (1-5s, INARI_CACHE_PEP_TTL) keyed (generation, user, relation, object).
// Both allows and denies are cached (deny-spam protection).
//
// Fail-open contract: any cache error degrades to a direct Check against the
// inner authorizer, logged (sampled) and metered; requests never fail
// because the cache is down.
//
// ListObjects is deliberately NOT cached: its callers are reconcilers, not
// the per-request PEP hot path; a stale membership set is more dangerous
// than a stale single check; and the spike flags it as the slowest but least
// frequent operation. The generation-stamped key scheme makes it safe to add
// later without redesign.
type CachedAuthorizer struct {
	inner    Authorizer
	cache    cache.Cache
	backend  string
	ttl      time.Duration
	failures atomic.Int64
}

// NewCachedAuthorizer wraps inner. backend labels metrics ("memory"|"redis").
func NewCachedAuthorizer(inner Authorizer, c cache.Cache, backend string, ttl time.Duration) *CachedAuthorizer {
	return &CachedAuthorizer{inner: inner, cache: c, backend: backend, ttl: ttl}
}

func pepKey(gen, user, relation, object string) string {
	return "inari:fga:pep:" + gen + ":" + user + "|" + relation + "|" + object
}

func (a *CachedAuthorizer) Check(ctx context.Context, user, relation, object string) (bool, error) {
	start := time.Now()
	key, cacheUp := a.key(ctx, user, relation, object)
	if cacheUp {
		switch v, hit, err := a.cache.Get(ctx, key); {
		case err != nil:
			a.failOpen(ctx, metrics.OpGet, err)
		case hit:
			metrics.RecordCacheOp(ctx, metrics.CachePEP, a.backend, metrics.OpGet, metrics.ResultHit)
			allowed := v == "1"
			metrics.ObserveFGACheck(ctx, time.Since(start), checkResult(allowed, nil), true)
			return allowed, nil
		default:
			metrics.RecordCacheOp(ctx, metrics.CachePEP, a.backend, metrics.OpGet, metrics.ResultMiss)
		}
	}
	allowed, err := a.inner.Check(ctx, user, relation, object)
	metrics.ObserveFGACheck(ctx, time.Since(start), checkResult(allowed, err), false)
	if err == nil && cacheUp {
		val := "0"
		if allowed {
			val = "1"
		}
		if serr := a.cache.Set(ctx, key, val, a.ttl); serr != nil {
			a.failOpen(ctx, metrics.OpSet, serr)
		}
	}
	return allowed, err
}

// ListObjects passes through uncached (see type doc).
func (a *CachedAuthorizer) ListObjects(ctx context.Context, user, relation, objectType string) ([]string, error) {
	return a.inner.ListObjects(ctx, user, relation, objectType)
}

// key resolves the generation-stamped cache key. cacheUp=false means the
// generation read failed and the caller must bypass the cache entirely.
func (a *CachedAuthorizer) key(ctx context.Context, user, relation, object string) (string, bool) {
	gen, _, err := a.cache.Get(ctx, pepGenerationKey)
	if err != nil {
		a.failOpen(ctx, metrics.OpGet, err)
		return "", false
	}
	if gen == "" {
		gen = "0"
	}
	return pepKey(gen, user, relation, object), true
}

// failOpen logs (first failure, then every 100th to avoid log spam during a
// Redis outage) and meters a cache error. The request always continues
// against the inner authorizer.
func (a *CachedAuthorizer) failOpen(ctx context.Context, op string, err error) {
	metrics.RecordCacheOp(ctx, metrics.CachePEP, a.backend, op, metrics.ResultError)
	if n := a.failures.Add(1); n == 1 || n%100 == 0 {
		slog.Warn("authz: pep cache error, failing open to OpenFGA", "op", op, "failures", n, "error", err)
	}
}

func checkResult(allowed bool, err error) string {
	if err != nil {
		return metrics.ResultError
	}
	if allowed {
		return metrics.ResultAllowed
	}
	return metrics.ResultDenied
}

// InvalidatingStore decorates a Store so every successful tuple write/delete
// bumps the PEP cache generation, invalidating all cached Check results at
// once. One hook covers every FGA write path (outbox TupleWriter,
// PlatformGroupSync, OrgTeamSync, tenancy.Deleter) because they all take a
// Store. A failed bump is fail-open: the write already succeeded, and TTL
// bounds staleness until the cache recovers.
type InvalidatingStore struct {
	inner   Store
	cache   cache.Cache
	backend string
}

// NewInvalidatingStore wraps inner. backend labels metrics.
func NewInvalidatingStore(inner Store, c cache.Cache, backend string) *InvalidatingStore {
	return &InvalidatingStore{inner: inner, cache: c, backend: backend}
}

func (s *InvalidatingStore) Check(ctx context.Context, user, relation, object string) (bool, error) {
	return s.inner.Check(ctx, user, relation, object)
}

func (s *InvalidatingStore) ListObjects(ctx context.Context, user, relation, objectType string) ([]string, error) {
	return s.inner.ListObjects(ctx, user, relation, objectType)
}

func (s *InvalidatingStore) ReadTuples(ctx context.Context, object, relation string) ([]Tuple, error) {
	return s.inner.ReadTuples(ctx, object, relation)
}

func (s *InvalidatingStore) WriteTuples(ctx context.Context, tuples []Tuple) error {
	if err := s.inner.WriteTuples(ctx, tuples); err != nil {
		return err
	}
	s.bump(ctx)
	return nil
}

func (s *InvalidatingStore) DeleteTuples(ctx context.Context, tuples []Tuple) error {
	if err := s.inner.DeleteTuples(ctx, tuples); err != nil {
		return err
	}
	s.bump(ctx)
	return nil
}

func (s *InvalidatingStore) bump(ctx context.Context) {
	if _, err := s.cache.Increment(ctx, pepGenerationKey); err != nil {
		metrics.RecordCacheOp(ctx, metrics.CachePEP, s.backend, metrics.OpIncrement, metrics.ResultError)
		slog.Warn("authz: pep cache invalidation failed (fail-open; TTL bounds staleness)", "error", err)
		return
	}
	metrics.RecordInvalidation(ctx, metrics.CachePEP)
}
