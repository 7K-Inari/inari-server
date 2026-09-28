// Package eventbus is the shared NATS client seam for the control plane
// (ADR-0014). It owns the core connection (auto-reconnect, connection-state
// metrics), the JetStream context, outbox stream provisioning, and the
// subject namespace convention:
//
//	Subject                          Transport            Persistence
//	inari.outbox.<event-type>        JetStream            durable (stream INARI_OUTBOX; PG outbox is the replay source)
//	inari.tunnel.<cluster>.<conn>    core NATS only       ephemeral, frames <= MaxTunnelFrame
//
// All subjects are rooted at inari.<domain>.<...>; tokens are lowercase and
// must not contain '.', '*', '>' or whitespace (ValidateSubjectToken). New
// domains must be registered in this package doc. JetStream subjects get
// durable at-least-once delivery via the outbox relay and per-handler
// consumer groups (internal/audit); core-NATS subjects are lossy by design
// (ephemeral low-latency pub/sub, e.g. the kubectl tunnel frame bus).
package eventbus

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/7K-Inari/inari-server/internal/metrics"
)

const (
	// StreamNameOutbox is the JetStream stream backing the transactional
	// outbox relay.
	StreamNameOutbox = "INARI_OUTBOX"
	// SubjectOutbox prefixes durable outbox event subjects.
	SubjectOutbox = "inari.outbox"
	// SubjectTunnel prefixes ephemeral kubectl tunnel frame subjects.
	SubjectTunnel = "inari.tunnel"
	// MaxTunnelFrame bounds one tunnel frame (32 KiB).
	MaxTunnelFrame = 32 << 10

	streamMaxAge      = 72 * time.Hour
	streamDedupWindow = 24 * time.Hour

	defaultConnectBudget = 2 * time.Minute
)

// OutboxSubject maps an outbox event type (e.g. "tenant.created") to its
// durable JetStream subject.
func OutboxSubject(eventType string) string { return SubjectOutbox + "." + eventType }

// ValidateSubjectToken rejects tokens that would corrupt subject structure.
func ValidateSubjectToken(s string) error {
	if s == "" {
		return fmt.Errorf("eventbus: subject token must not be empty")
	}
	for _, r := range s {
		if r == '.' || r == '*' || r == '>' || unicode.IsSpace(r) {
			return fmt.Errorf("eventbus: subject token %q must not contain '.', '*', '>' or whitespace", s)
		}
	}
	return nil
}

// TunnelSubject builds the ephemeral frame-bus subject for one tunnel
// connection (inari.tunnel.<clusterID>.<connID>).
func TunnelSubject(clusterID, connID string) (string, error) {
	if err := ValidateSubjectToken(clusterID); err != nil {
		return "", err
	}
	if err := ValidateSubjectToken(connID); err != nil {
		return "", err
	}
	return SubjectTunnel + "." + clusterID + "." + connID, nil
}

// ValidateTunnelFrame enforces the 32 KiB tunnel frame bound.
func ValidateTunnelFrame(frame []byte) error {
	if len(frame) > MaxTunnelFrame {
		return fmt.Errorf("eventbus: tunnel frame %d bytes exceeds %d", len(frame), MaxTunnelFrame)
	}
	return nil
}

// Bus is the shared NATS handle: one core connection plus its JetStream
// context.
type Bus struct {
	nc *nats.Conn
	js jetstream.JetStream
}

type config struct {
	connectBudget time.Duration
}

// Option customizes Connect.
type Option func(*config)

// WithConnectBudget overrides the startup retry budget (tests).
func WithConnectBudget(d time.Duration) Option {
	return func(c *config) { c.connectBudget = d }
}

// Connect dials NATS and returns the shared Bus. NATS is obligatory
// infrastructure (ADR-0014): a startup failure after the retry budget is
// fatal. The budget absorbs first-install ordering when the chart's
// default-on subchart pod is still starting — no helm ordering hooks needed.
// Runtime drops are fail-open: the client auto-reconnects, connection state
// is metered, and outbox rows accumulate unpublished until the bus heals.
func Connect(ctx context.Context, url string, opts ...Option) (*Bus, error) {
	cfg := config{connectBudget: defaultConnectBudget}
	for _, o := range opts {
		o(&cfg)
	}
	natsOpts := []nats.Option{
		nats.Name("inari-server"),
		nats.Timeout(5 * time.Second),
		nats.ReconnectHandler(func(*nats.Conn) {
			metrics.SetNATSConnected(context.Background(), true)
			metrics.RecordNATSReconnect(context.Background())
		}),
		nats.DisconnectErrHandler(func(*nats.Conn, error) {
			metrics.SetNATSConnected(context.Background(), false)
		}),
		nats.ClosedHandler(func(*nats.Conn) {
			metrics.SetNATSConnected(context.Background(), false)
		}),
	}
	deadline := time.Now().Add(cfg.connectBudget)
	backoff := time.Second
	var nc *nats.Conn
	for {
		var err error
		nc, err = nats.Connect(url, natsOpts...)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if time.Now().Add(backoff).After(deadline) {
			return nil, fmt.Errorf("eventbus: connect %s: %w (retry budget %s exhausted)", url, err, cfg.connectBudget)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < 5*time.Second {
			backoff += time.Second
		}
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("eventbus: jetstream context: %w", err)
	}
	metrics.SetNATSConnected(context.Background(), true)
	return &Bus{nc: nc, js: js}, nil
}

// EnsureOutboxStream creates-or-updates the outbox stream: limits retention
// (PG outbox remains the replay source), Nats-Msg-Id dedup within a 24h
// window, R=replicas. Idempotent; replica changes (e.g. 1->3) reconcile
// online without recreating the stream.
func (b *Bus) EnsureOutboxStream(ctx context.Context, replicas int) error {
	if replicas < 1 {
		replicas = 1
	}
	_, err := b.js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:       StreamNameOutbox,
		Subjects:   []string{SubjectOutbox + ".>"},
		Retention:  jetstream.LimitsPolicy,
		Storage:    jetstream.FileStorage,
		Discard:    jetstream.DiscardOld,
		MaxAge:     streamMaxAge,
		Duplicates: streamDedupWindow,
		Replicas:   replicas,
	})
	if err != nil {
		return fmt.Errorf("eventbus: ensure stream %s: %w", StreamNameOutbox, err)
	}
	return nil
}

// JetStream exposes the JetStream context (outbox relay, consumers).
func (b *Bus) JetStream() jetstream.JetStream { return b.js }

// Publish sends one ephemeral core-NATS message (no persistence, lossy by
// design). Failures are returned, metered by subject domain, and must be
// logged by the caller — never fatal.
func (b *Bus) Publish(_ context.Context, subject string, data []byte) error {
	if err := b.nc.Publish(subject, data); err != nil {
		metrics.RecordEphemeralError(context.Background(), domainOf(subject))
		return fmt.Errorf("eventbus: publish %s: %w", subject, err)
	}
	return nil
}

// Subscribe registers an ephemeral core-NATS subscription; the returned
// function unsubscribes.
func (b *Bus) Subscribe(subject string, cb func(subject string, data []byte)) (func() error, error) {
	sub, err := b.nc.Subscribe(subject, func(m *nats.Msg) { cb(m.Subject, m.Data) })
	if err != nil {
		return nil, fmt.Errorf("eventbus: subscribe %s: %w", subject, err)
	}
	return sub.Unsubscribe, nil
}

// Close drains the connection (in-flight publishes flush, subscriptions end).
func (b *Bus) Close() { _ = b.nc.Drain() }

// domainOf extracts the subject domain (second token) for metrics labels.
func domainOf(subject string) string {
	parts := strings.SplitN(subject, ".", 3)
	if len(parts) == 3 {
		return parts[1]
	}
	return "unknown"
}
