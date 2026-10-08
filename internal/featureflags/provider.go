package featureflags

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/open-feature/go-sdk/openfeature"

	"github.com/7K-Inari/inari-server/internal/cache"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/metrics"
)

// Evaluation-context attribute keys understood by DBProvider.
const (
	// AttrScope selects the evaluation scope ("cluster" to consult a
	// per-cluster override; anything else evaluates the platform default).
	AttrScope = "scope"
	// AttrClusterID carries the cluster id for cluster-scoped evaluation.
	AttrClusterID = "clusterId"
)

// ProviderDomain is the OpenFeature named-provider domain Inari registers
// its DB provider under.
const ProviderDomain = "inari"

// DBProvider is the built-in OpenFeature provider: flag values from the
// feature_flags table, resolution cluster override → platform default →
// built-in default. Effective values are cached in the shared cache keyed by
// (generation, flag, scopeKey); the generation bumps on every flag write
// (Service.bump), so replicas and the kubeproxy converge without polling,
// and the TTL bounds staleness when the cache is per-process memory.
//
// Fail-open contract: any store/cache error resolves to the flag's built-in
// default with reason ERROR — a flags outage must never 500 a request or
// silently flip a kill switch.
type DBProvider struct {
	q        db.Querier
	store    *Store
	cache    cache.Cache
	backend  string
	ttl      time.Duration
	failures atomic.Int64
}

// NewDBProvider builds the provider. cache may be nil (no caching).
func NewDBProvider(q db.Querier, store *Store, c cache.Cache, backend string, ttl time.Duration) *DBProvider {
	return &DBProvider{q: q, store: store, cache: c, backend: backend, ttl: ttl}
}

// Metadata implements openfeature.FeatureProvider.
func (p *DBProvider) Metadata() openfeature.Metadata {
	return openfeature.Metadata{Name: "inari-db"}
}

// Hooks implements openfeature.FeatureProvider.
func (p *DBProvider) Hooks() []openfeature.Hook { return nil }

// BooleanEvaluation implements openfeature.FeatureProvider.
func (p *DBProvider) BooleanEvaluation(ctx context.Context, flag string, defaultValue bool, flatCtx openfeature.FlattenedContext) openfeature.BoolResolutionDetail {
	def, ok := Lookup(flag)
	if !ok || def.Type != FlagTypeBoolean {
		return boolDetail(defaultValue, openfeature.NewFlagNotFoundResolutionError(fmt.Sprintf("flag %q is not registered", flag)))
	}
	clusterID, _ := flatCtx[AttrClusterID].(string)
	if scope, _ := flatCtx[AttrScope].(string); scope != string(ScopeCluster) {
		clusterID = ""
	}
	value, err := p.resolve(ctx, def, clusterID)
	if err != nil {
		p.failOpen(ctx, err)
		return boolDetail(def.Default, openfeature.NewGeneralResolutionError("flag store unavailable; resolved to built-in default", err))
	}
	return openfeature.BoolResolutionDetail{
		Value: value,
		ProviderResolutionDetail: openfeature.ProviderResolutionDetail{
			Reason:  openfeature.StaticReason,
			Variant: variant(value),
		},
	}
}

// resolve applies the precedence chain: cluster override → platform row →
// built-in default. The effective result is cached per (generation, flag,
// scopeKey); a missing row and a row value are cached alike (negative
// caching avoids a DB hit per proxied request).
func (p *DBProvider) resolve(ctx context.Context, def Definition, clusterID string) (bool, error) {
	if p.cache != nil {
		if v, ok, err := p.cached(ctx, def.Key, clusterID); err != nil {
			p.failOpenCache(ctx, metrics.OpGet, err)
		} else if ok {
			metrics.RecordCacheOp(ctx, metrics.CacheFlags, p.backend, metrics.OpGet, metrics.ResultHit)
			return v, nil
		}
		metrics.RecordCacheOp(ctx, metrics.CacheFlags, p.backend, metrics.OpGet, metrics.ResultMiss)
	}
	value, err := p.resolveUncached(ctx, def, clusterID)
	if err != nil {
		return false, err
	}
	if p.cache != nil {
		if err := p.setCached(ctx, def.Key, clusterID, value); err != nil {
			p.failOpenCache(ctx, metrics.OpSet, err)
		}
	}
	return value, nil
}

func (p *DBProvider) resolveUncached(ctx context.Context, def Definition, clusterID string) (bool, error) {
	if clusterID != "" && def.AllowsScope(ScopeCluster) {
		row, err := p.store.Get(ctx, p.q, def.Key, ScopeCluster, clusterID)
		if err != nil {
			return false, err
		}
		if row != nil {
			return row.Value, nil
		}
	}
	row, err := p.store.Get(ctx, p.q, def.Key, ScopePlatform, "")
	if err != nil {
		return false, err
	}
	if row != nil {
		return row.Value, nil
	}
	return def.Default, nil
}

func flagCacheKey(gen, flag, scopeKey string) string {
	return "inari:flags:" + gen + ":" + flag + "|" + scopeKey
}

// cached reads the generation-stamped effective value; ok=false on miss.
func (p *DBProvider) cached(ctx context.Context, flag, scopeKey string) (bool, bool, error) {
	gen, _, err := p.cache.Get(ctx, GenerationKey)
	if err != nil {
		return false, false, err
	}
	if gen == "" {
		gen = "0"
	}
	v, hit, err := p.cache.Get(ctx, flagCacheKey(gen, flag, scopeKey))
	if err != nil || !hit {
		return false, false, err
	}
	return v == "1", true, nil
}

func (p *DBProvider) setCached(ctx context.Context, flag, scopeKey string, value bool) error {
	gen, _, err := p.cache.Get(ctx, GenerationKey)
	if err != nil {
		return err
	}
	if gen == "" {
		gen = "0"
	}
	v := "0"
	if value {
		v = "1"
	}
	return p.cache.Set(ctx, flagCacheKey(gen, flag, scopeKey), v, p.ttl)
}

func boolDetail(value bool, resErr openfeature.ResolutionError) openfeature.BoolResolutionDetail {
	return openfeature.BoolResolutionDetail{
		Value: value,
		ProviderResolutionDetail: openfeature.ProviderResolutionDetail{
			Reason:          openfeature.DefaultReason,
			Variant:         variant(value),
			ResolutionError: resErr,
		},
	}
}

func variant(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

// failOpen logs (sampled) a store error; the caller resolves to the built-in
// default.
func (p *DBProvider) failOpen(ctx context.Context, err error) {
	if n := p.failures.Add(1); n == 1 || n%100 == 0 {
		slog.Warn("featureflags: store error, resolving to built-in default", "failures", n, "error", err)
	}
}

func (p *DBProvider) failOpenCache(ctx context.Context, op string, err error) {
	metrics.RecordCacheOp(ctx, metrics.CacheFlags, p.backend, op, metrics.ResultError)
	if n := p.failures.Add(1); n == 1 || n%100 == 0 {
		slog.Warn("featureflags: cache error, failing open to Postgres", "op", op, "failures", n, "error", err)
	}
}

// StringEvaluation implements openfeature.FeatureProvider (v1: unsupported).
func (p *DBProvider) StringEvaluation(_ context.Context, flag string, defaultValue string, _ openfeature.FlattenedContext) openfeature.StringResolutionDetail {
	return openfeature.StringResolutionDetail{
		Value: defaultValue,
		ProviderResolutionDetail: openfeature.ProviderResolutionDetail{
			Reason:          openfeature.ErrorReason,
			ResolutionError: openfeature.NewGeneralResolutionError("flag "+flag+": only boolean flags are supported", nil),
		},
	}
}

// FloatEvaluation implements openfeature.FeatureProvider (v1: unsupported).
func (p *DBProvider) FloatEvaluation(_ context.Context, flag string, defaultValue float64, _ openfeature.FlattenedContext) openfeature.FloatResolutionDetail {
	return openfeature.FloatResolutionDetail{
		Value: defaultValue,
		ProviderResolutionDetail: openfeature.ProviderResolutionDetail{
			Reason:          openfeature.ErrorReason,
			ResolutionError: openfeature.NewGeneralResolutionError("flag "+flag+": only boolean flags are supported", nil),
		},
	}
}

// IntEvaluation implements openfeature.FeatureProvider (v1: unsupported).
func (p *DBProvider) IntEvaluation(_ context.Context, flag string, defaultValue int64, _ openfeature.FlattenedContext) openfeature.IntResolutionDetail {
	return openfeature.IntResolutionDetail{
		Value: defaultValue,
		ProviderResolutionDetail: openfeature.ProviderResolutionDetail{
			Reason:          openfeature.ErrorReason,
			ResolutionError: openfeature.NewGeneralResolutionError("flag "+flag+": only boolean flags are supported", nil),
		},
	}
}

// ObjectEvaluation implements openfeature.FeatureProvider (v1: unsupported).
func (p *DBProvider) ObjectEvaluation(_ context.Context, flag string, defaultValue any, _ openfeature.FlattenedContext) openfeature.InterfaceResolutionDetail {
	return openfeature.InterfaceResolutionDetail{
		Value: defaultValue,
		ProviderResolutionDetail: openfeature.ProviderResolutionDetail{
			Reason:          openfeature.ErrorReason,
			ResolutionError: openfeature.NewGeneralResolutionError("flag "+flag+": only boolean flags are supported", nil),
		},
	}
}
