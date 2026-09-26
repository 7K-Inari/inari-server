// Package metrics is the control plane's OTel metrics seam: a Prometheus
// exporter mounted at /metrics plus the shared instruments for the cache
// layer (ADR-0010). Instruments are created from the global meter provider
// (set by New) so call sites never thread a provider through constructors.
package metrics

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	promclient "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// Cache label values.
const (
	CachePEP    = "pep"
	CacheTenant = "tenant"
)

// Operation label values.
const (
	OpGet       = "get"
	OpSet       = "set"
	OpDelete    = "delete"
	OpIncrement = "increment"
)

// Result label values.
const (
	ResultHit     = "hit"
	ResultMiss    = "miss"
	ResultError   = "error"
	ResultAllowed = "allowed"
	ResultDenied  = "denied"
)

var (
	meter = otel.Meter("github.com/7K-Inari/inari-server")

	cacheOps, _ = meter.Int64Counter("inari.cache.operations",
		metric.WithDescription("Cache operations by cache, backend, operation, and result."))
	cacheInvalidations, _ = meter.Int64Counter("inari.cache.invalidations",
		metric.WithDescription("Cache invalidation events by cache."))
	fgaChecks, _ = meter.Int64Counter("inari.fga.check",
		metric.WithDescription("OpenFGA Check evaluations, tagged by whether the result came from the PEP cache."))
	fgaCheckDuration, _ = meter.Float64Histogram("inari.fga.check.duration",
		metric.WithDescription("OpenFGA Check latency in seconds (uncached calls measure the FGA round trip)."),
		metric.WithUnit("s"))
)

// New builds a Prometheus exporter on its own registry and installs the
// MeterProvider globally. The returned handler serves /metrics; shutdown
// flushes and releases the provider.
func New() (http.Handler, func(context.Context) error, error) {
	reg := promclient.NewRegistry()
	exp, err := otelprom.New(otelprom.WithRegisterer(reg))
	if err != nil {
		return nil, nil, fmt.Errorf("metrics: prometheus exporter: %w", err)
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exp))
	otel.SetMeterProvider(mp)
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{}), mp.Shutdown, nil
}

// RecordCacheOp counts one cache operation (hit/miss/error drives the hit
// ratio). Fail-open degradation shows up as result=error.
func RecordCacheOp(ctx context.Context, cacheName, backend, op, result string) {
	cacheOps.Add(ctx, 1, metric.WithAttributes(
		attribute.String("cache", cacheName),
		attribute.String("backend", backend),
		attribute.String("op", op),
		attribute.String("result", result),
	))
}

// RecordInvalidation counts one invalidation (PEP generation bump or tenant
// slug eviction).
func RecordInvalidation(ctx context.Context, cacheName string) {
	cacheInvalidations.Add(ctx, 1, metric.WithAttributes(attribute.String("cache", cacheName)))
}

// ObserveFGACheck records an OpenFGA Check evaluation: latency + allow/deny/
// error result, tagged cached=true|false. This is the primary evidence for
// the PEP cache p99 win (spike m1-openfga-performance).
func ObserveFGACheck(ctx context.Context, d time.Duration, result string, cached bool) {
	attrs := metric.WithAttributes(
		attribute.String("result", result),
		attribute.String("cached", strconv.FormatBool(cached)),
	)
	fgaChecks.Add(ctx, 1, attrs)
	fgaCheckDuration.Record(ctx, d.Seconds(), attrs)
}
