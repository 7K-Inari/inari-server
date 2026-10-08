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
	CacheFlags  = "flags"
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

// Outbox consumer delivery result label values (ADR-0014).
const (
	ResultAck        = "ack"
	ResultRetry      = "retry"
	ResultDeadletter = "deadletter"
	ResultSkip       = "skip"
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

	outboxRelayPublished, _ = meter.Int64Counter("inari.outbox.relay.published",
		metric.WithDescription("Outbox rows relayed to JetStream (ADR-0014)."))
	outboxRelayErrors, _ = meter.Int64Counter("inari.outbox.relay.errors",
		metric.WithDescription("Outbox relay publish failures; rows stay unpublished and retry."))
	outboxUnpublished, _ = meter.Int64Gauge("inari.outbox.unpublished",
		metric.WithDescription("Outbox backlog depth (rows awaiting relay); the primary NATS-degradation signal."))
	consumerDeliveries, _ = meter.Int64Counter("inari.outbox.consumer.deliveries",
		metric.WithDescription("Outbox consumer deliveries by handler and result (ack, retry, deadletter, skip)."))
	consumerDuration, _ = meter.Float64Histogram("inari.outbox.consumer.duration",
		metric.WithDescription("Outbox handler execution latency in seconds."),
		metric.WithUnit("s"))
	natsConnectionState, _ = meter.Int64Gauge("inari.nats.connection.state",
		metric.WithDescription("NATS connection state: 1 connected, 0 disconnected."))
	natsReconnects, _ = meter.Int64Counter("inari.nats.reconnects",
		metric.WithDescription("NATS reconnect events."))
	ephemeralErrors, _ = meter.Int64Counter("inari.eventbus.ephemeral.errors",
		metric.WithDescription("Ephemeral core-NATS publish failures by subject domain (lossy by design)."))

	kubeproxyConns, _ = meter.Int64Counter("inari.kubeproxy.connections",
		metric.WithDescription("Proxied kubectl connections by result (open, close, byte_cap_exceeded, no_tunnel)."))
	kubeproxySessions, _ = meter.Int64UpDownCounter("inari.kubeproxy.tunnel_sessions",
		metric.WithDescription("Live tunnel-agent sessions by event (register, unregister)."))
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

// RecordRelayPublished counts outbox rows successfully relayed to JetStream.
func RecordRelayPublished(ctx context.Context, n int64) {
	if n > 0 {
		outboxRelayPublished.Add(ctx, n)
	}
}

// RecordRelayError counts one relay publish failure (the row stays
// unpublished and is retried — fail-open, never fatal at runtime).
func RecordRelayError(ctx context.Context) {
	outboxRelayErrors.Add(ctx, 1)
}

// SetOutboxUnpublished samples the outbox backlog depth after each relay
// poll. A rising value with a healthy API means NATS degradation.
func SetOutboxUnpublished(ctx context.Context, n int64) {
	outboxUnpublished.Record(ctx, n)
}

// RecordConsumerDelivery counts one consumer delivery attempt and observes
// handler latency (zero for skip).
func RecordConsumerDelivery(ctx context.Context, handler, result string, d time.Duration) {
	attrs := metric.WithAttributes(
		attribute.String("handler", handler),
		attribute.String("result", result),
	)
	consumerDeliveries.Add(ctx, 1, attrs)
	if result == ResultAck {
		consumerDuration.Record(ctx, d.Seconds(), metric.WithAttributes(attribute.String("handler", handler)))
	}
}

// SetNATSConnected tracks the core NATS connection state.
func SetNATSConnected(ctx context.Context, connected bool) {
	var v int64
	if connected {
		v = 1
	}
	natsConnectionState.Record(ctx, v)
}

// RecordNATSReconnect counts one reconnect after a connection drop.
func RecordNATSReconnect(ctx context.Context) {
	natsReconnects.Add(ctx, 1)
}

// RecordEphemeralError counts one ephemeral core-NATS publish failure by
// subject domain (e.g. tunnel). Lossy by design — logged and metered, never
// fatal.
func RecordEphemeralError(ctx context.Context, domain string) {
	ephemeralErrors.Add(ctx, 1, metric.WithAttributes(attribute.String("domain", domain)))
}

// Kubeproxy connection result label values (plan §7.2).
const (
	KubeproxyOpen              = "open"
	KubeproxyClose             = "close"
	KubeproxyByteCapExceeded   = "byte_cap_exceeded"
	KubeproxyNoTunnel          = "no_tunnel"
	KubeproxySessionRegister   = "register"
	KubeproxySessionUnregister = "unregister"
)

// RecordKubeproxyConn counts one proxied kubectl connection event.
func RecordKubeproxyConn(ctx context.Context, result string) {
	kubeproxyConns.Add(ctx, 1, metric.WithAttributes(attribute.String("result", result)))
}

// RecordKubeproxySession tracks the live tunnel-session count.
func RecordKubeproxySession(ctx context.Context, event string) {
	var v int64 = 1
	if event != KubeproxySessionRegister {
		v = -1
	}
	kubeproxySessions.Add(ctx, v, metric.WithAttributes(attribute.String("event", event)))
}
