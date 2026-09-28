package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/eventbus"
	"github.com/7K-Inari/inari-server/internal/metrics"
	"github.com/7K-Inari/inari-server/internal/types"
)

// Delivery budgets (ADR-0014). The relay budget bounds publish attempts for
// one outbox row; the consumer budget bounds handler deliveries per event.
const (
	DefaultMaxPublishAttempts = 50
	DefaultMaxDeliver         = 50

	defaultPublishAckBudget = 10 * time.Second
	defaultConsumerAckWait  = 30 * time.Second
	fetchBatch              = 32
)

// handlerNameRE pins durable consumer names (outbox-<name>): stable across
// deploys, safe as a NATS durable name and a metrics label.
var handlerNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// NamedHandler pairs a Handler with the stable name used for its durable
// JetStream consumer group and metrics labels.
type NamedHandler struct {
	name string
	Handler
}

// Named wraps h under a stable name (validated by NewDispatcher).
func Named(name string, h Handler) NamedHandler { return NamedHandler{name: name, Handler: h} }

// Name returns the handler's durable consumer group name suffix.
func (n NamedHandler) Name() string { return n.name }

func (n NamedHandler) handles(eventType string) bool {
	for _, t := range n.EventTypes() {
		if t == eventType {
			return true
		}
	}
	return false
}

// backoffSchedule returns the per-redelivery delay list: 1s, 2s, 5s, 10s,
// then 30s capped, one entry per delivery.
func backoffSchedule(maxDeliver int) []time.Duration {
	base := []time.Duration{time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second}
	out := make([]time.Duration, 0, maxDeliver)
	for i := 0; i < maxDeliver; i++ {
		if i < len(base) {
			out = append(out, base[i])
		} else {
			out = append(out, 30*time.Second)
		}
	}
	return out
}

// NATSPublisher implements the Publisher seam over JetStream: durable
// at-least-once publish with Nats-Msg-Id dedup keyed by outbox row ID.
type NATSPublisher struct {
	js jetstream.JetStream
}

// NewNATSPublisher builds a Publisher over the shared bus.
func NewNATSPublisher(bus *eventbus.Bus) *NATSPublisher {
	return &NATSPublisher{js: bus.JetStream()}
}

// Publish delivers one outbox event to inari.outbox.<event-type>.
func (p *NATSPublisher) Publish(ctx context.Context, ev *types.OutboxEvent) error {
	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("outbox: marshal event %d: %w", ev.ID, err)
	}
	_, err = p.js.Publish(ctx, eventbus.OutboxSubject(ev.EventType), data,
		jetstream.WithMsgID(strconv.FormatInt(ev.ID, 10)))
	return err
}

// Dispatcher relays unpublished outbox rows to JetStream and delivers them
// to per-handler durable consumer groups (ADR-0014). Multi-replica safe
// without a leader lease: the relay claims rows with FOR UPDATE SKIP LOCKED
// and JetStream load-balances deliveries inside each durable group, so every
// handler sees each event exactly-once-ish cluster-wide.
type Dispatcher struct {
	db                 *db.DB
	js                 jetstream.JetStream
	interval           time.Duration
	batch              int
	maxPublishAttempts int
	maxDeliver         int
	publishAckBudget   time.Duration
	consumerAckWait    time.Duration
	handlers           []NamedHandler
	consumers          map[string]jetstream.Consumer
}

// DispatcherOption customizes the Dispatcher (tests).
type DispatcherOption func(*Dispatcher)

// WithMaxDeliver overrides the per-event handler delivery budget (tests
// drive terminal dead-letters with small values).
func WithMaxDeliver(n int) DispatcherOption {
	return func(d *Dispatcher) {
		if n > 0 {
			d.maxDeliver = n
		}
	}
}

// WithPublishAckBudget overrides the per-batch publish ack timeout (tests
// exercise NATS-down failure paths without waiting 10s).
func WithPublishAckBudget(b time.Duration) DispatcherOption {
	return func(d *Dispatcher) {
		if b > 0 {
			d.publishAckBudget = b
		}
	}
}

// WithConsumerAckWait overrides the consumer ack wait (tests exercise
// shutdown redelivery without waiting 30s).
func WithConsumerAckWait(w time.Duration) DispatcherOption {
	return func(d *Dispatcher) {
		if w > 0 {
			d.consumerAckWait = w
		}
	}
}

// NewDispatcher creates-or-updates one durable pull consumer per handler:
// DeliverAll (a late-created or renamed durable never misses events already
// in the stream), explicit ack, MaxDeliver with a capped backoff schedule,
// filter inari.outbox.> with client-side event-type match.
func NewDispatcher(ctx context.Context, d *db.DB, bus *eventbus.Bus, interval time.Duration, handlers []NamedHandler, opts ...DispatcherOption) (*Dispatcher, error) {
	if interval <= 0 {
		interval = time.Second
	}
	disp := &Dispatcher{
		db:                 d,
		js:                 bus.JetStream(),
		interval:           interval,
		batch:              100,
		maxPublishAttempts: DefaultMaxPublishAttempts,
		maxDeliver:         DefaultMaxDeliver,
		publishAckBudget:   defaultPublishAckBudget,
		consumerAckWait:    defaultConsumerAckWait,
		consumers:          map[string]jetstream.Consumer{},
	}
	for _, o := range opts {
		o(disp)
	}
	for _, h := range handlers {
		if !handlerNameRE.MatchString(h.name) {
			return nil, fmt.Errorf("outbox: invalid handler name %q (want %s)", h.name, handlerNameRE)
		}
		if _, dup := disp.consumers[h.name]; dup {
			return nil, fmt.Errorf("outbox: duplicate handler name %q", h.name)
		}
		cons, err := disp.js.CreateOrUpdateConsumer(ctx, eventbus.StreamNameOutbox, jetstream.ConsumerConfig{
			Durable:       "outbox-" + h.name,
			AckPolicy:     jetstream.AckExplicitPolicy,
			AckWait:       disp.consumerAckWait,
			MaxDeliver:    disp.maxDeliver,
			DeliverPolicy: jetstream.DeliverAllPolicy,
			FilterSubject: eventbus.SubjectOutbox + ".>",
			BackOff:       backoffSchedule(disp.maxDeliver),
		})
		if err != nil {
			return nil, fmt.Errorf("outbox: consumer for handler %q: %w", h.name, err)
		}
		disp.consumers[h.name] = cons
		disp.handlers = append(disp.handlers, h)
	}
	return disp, nil
}

// Run starts the relay loop plus one consumer loop per handler until ctx is
// cancelled. On shutdown, in-flight deliveries are Nak'd so a surviving
// replica picks them up immediately rather than after the ack wait.
func (d *Dispatcher) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, h := range d.handlers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.consumeLoop(ctx, h)
		}()
	}
	tick := time.NewTicker(d.interval)
	defer tick.Stop()
	for {
		_ = d.RelayOnce(ctx)
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case <-tick.C:
		}
	}
}

// RelayOnce claims one batch of unpublished outbox rows (FOR UPDATE SKIP
// LOCKED), publishes each to JetStream with Nats-Msg-Id dedup inside the
// claim TX, and marks rows published only after the PubAck — a crash after
// ack but before commit republishes, which the 24h dedup window collapses;
// a NATS outage leaves rows unpublished to drain on recovery (fail-open).
func (d *Dispatcher) RelayOnce(ctx context.Context) error {
	err := d.db.WithTx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, org_id, event_type, payload, occurred_at, attempts FROM outbox
			 WHERE published_at IS NULL ORDER BY id LIMIT $1 FOR UPDATE SKIP LOCKED`, d.batch)
		if err != nil {
			return fmt.Errorf("outbox: poll: %w", err)
		}
		var events []types.OutboxEvent
		for rows.Next() {
			var ev types.OutboxEvent
			if err := rows.Scan(&ev.ID, &ev.OrgID, &ev.EventType, &ev.Payload, &ev.OccurredAt, &ev.Attempts); err != nil {
				rows.Close()
				return err
			}
			events = append(events, ev)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		type pending struct {
			ev     *types.OutboxEvent
			fut    jetstream.PubAckFuture
			pubErr error
		}
		pubs := make([]pending, 0, len(events))
		for i := range events {
			ev := &events[i]
			data, err := json.Marshal(ev)
			if err != nil {
				pubs = append(pubs, pending{ev: ev, pubErr: fmt.Errorf("outbox: marshal: %w", err)})
				continue
			}
			fut, err := d.js.PublishAsync(eventbus.OutboxSubject(ev.EventType), data,
				jetstream.WithMsgID(strconv.FormatInt(ev.ID, 10)))
			if err != nil {
				pubs = append(pubs, pending{ev: ev, pubErr: fmt.Errorf("outbox: publish: %w", err)})
				continue
			}
			pubs = append(pubs, pending{ev: ev, fut: fut})
		}

		deadline := time.Now().Add(d.publishAckBudget)
		var relayed int64
		for i := range pubs {
			p := &pubs[i]
			if p.pubErr == nil {
				remaining := time.Until(deadline)
				if remaining <= 0 {
					p.pubErr = fmt.Errorf("outbox: publish ack budget %s exhausted", d.publishAckBudget)
				} else {
					timer := time.NewTimer(remaining)
					select {
					case <-p.fut.Ok():
					case e := <-p.fut.Err():
						p.pubErr = fmt.Errorf("outbox: publish ack: %w", e)
					case <-timer.C:
						p.pubErr = fmt.Errorf("outbox: publish ack budget %s exhausted", d.publishAckBudget)
					}
					timer.Stop()
				}
			}
			if p.pubErr != nil {
				metrics.RecordRelayError(ctx)
				if _, err := tx.Exec(ctx,
					`UPDATE outbox SET attempts = attempts + 1, last_error = $2,
					 published_at = CASE WHEN attempts + 1 >= $3 THEN now() ELSE published_at END
					 WHERE id = $1`, p.ev.ID, p.pubErr.Error(), d.maxPublishAttempts); err != nil {
					return err
				}
				if p.ev.Attempts+1 >= d.maxPublishAttempts {
					slog.Error("outbox: dead-lettering unpublishable event",
						"id", p.ev.ID, "type", p.ev.EventType, "attempts", p.ev.Attempts+1, "error", p.pubErr)
				}
				continue
			}
			relayed++
			if _, err := tx.Exec(ctx, `UPDATE outbox SET published_at = now(), last_error = '' WHERE id = $1`, p.ev.ID); err != nil {
				return err
			}
		}
		metrics.RecordRelayPublished(ctx, relayed)
		return nil
	})
	if err != nil {
		return err
	}
	var backlog int64
	if err := d.db.Pool.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE published_at IS NULL`).Scan(&backlog); err == nil {
		metrics.SetOutboxUnpublished(ctx, backlog)
	}
	return nil
}

// DeliverOnce synchronously drains currently-pending messages for every
// handler (test drive path; Run uses consumeLoop instead).
func (d *Dispatcher) DeliverOnce(ctx context.Context) (int, error) {
	total := 0
	for _, h := range d.handlers {
		cons := d.consumers[h.name]
		for {
			batch, err := cons.Fetch(fetchBatch, jetstream.FetchMaxWait(500*time.Millisecond))
			if err != nil {
				return total, fmt.Errorf("outbox: fetch %s: %w", h.name, err)
			}
			n := 0
			for msg := range batch.Messages() {
				n++
				if !d.deliver(ctx, h, msg) {
					return total, ctx.Err()
				}
			}
			total += n
			if berr := batch.Error(); berr != nil && !errors.Is(berr, jetstream.ErrNoMessages) {
				return total, fmt.Errorf("outbox: fetch %s: %w", h.name, berr)
			}
			if n < fetchBatch {
				break
			}
		}
	}
	return total, nil
}

// consumeLoop pulls deliveries for one handler until ctx is cancelled.
func (d *Dispatcher) consumeLoop(ctx context.Context, h NamedHandler) {
	cons := d.consumers[h.name]
	for ctx.Err() == nil {
		batch, err := cons.Fetch(fetchBatch, jetstream.FetchMaxWait(2*time.Second))
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("outbox: consumer fetch failed (fail-open, retrying)",
				"handler", h.name, "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}
		for msg := range batch.Messages() {
			if !d.deliver(ctx, h, msg) {
				// Shutdown: Nak anything else the in-flight pull delivers so
				// a surviving replica isn't gated on the ack wait.
				for rest := range batch.Messages() {
					_ = rest.Nak()
				}
				return
			}
		}
		if berr := batch.Error(); berr != nil && !errors.Is(berr, jetstream.ErrNoMessages) && ctx.Err() == nil {
			slog.Warn("outbox: consumer batch error (fail-open, continuing)",
				"handler", h.name, "error", berr)
		}
	}
}

// deliver processes one message: skip non-matching event types, ack on
// success, Nak for redelivery on failure, and dead-letter (write last_error
// back to the outbox row + terminal ack) once the delivery budget is
// exhausted. Returns false when ctx was cancelled mid-delivery (message
// already Nak'd for immediate pickup by a surviving replica).
func (d *Dispatcher) deliver(ctx context.Context, h NamedHandler, msg jetstream.Msg) bool {
	var ev types.OutboxEvent
	if err := json.Unmarshal(msg.Data(), &ev); err != nil {
		slog.Error("outbox: undecodable message (terminal)",
			"handler", h.name, "subject", msg.Subject(), "error", err)
		_ = msg.Ack()
		metrics.RecordConsumerDelivery(ctx, h.name, metrics.ResultDeadletter, 0)
		return true
	}
	if !h.handles(ev.EventType) {
		_ = msg.Ack()
		metrics.RecordConsumerDelivery(ctx, h.name, metrics.ResultSkip, 0)
		return true
	}
	start := time.Now()
	err := h.Handle(ctx, &ev)
	if err == nil {
		_ = msg.Ack()
		metrics.RecordConsumerDelivery(ctx, h.name, metrics.ResultAck, time.Since(start))
		return true
	}
	if ctx.Err() != nil {
		_ = msg.Nak()
		return false
	}
	var delivered uint64
	if md, mdErr := msg.Metadata(); mdErr == nil {
		delivered = md.NumDelivered
	}
	if delivered >= uint64(d.maxDeliver) {
		// Terminal dead-letter: write last_error back onto the already-
		// published row so one SQL query still finds all dead-letters with
		// the payload co-located for replay (ADR-0014).
		if _, dbErr := d.db.Pool.Exec(context.Background(),
			`UPDATE outbox SET last_error = $2 WHERE id = $1`, ev.ID, err.Error()); dbErr != nil {
			slog.Error("outbox: dead-letter write-back failed", "id", ev.ID, "error", dbErr)
		}
		slog.Error("outbox: dead-lettering poison event",
			"handler", h.name, "id", ev.ID, "type", ev.EventType, "deliveries", delivered, "error", err)
		_ = msg.Ack()
		metrics.RecordConsumerDelivery(ctx, h.name, metrics.ResultDeadletter, time.Since(start))
		return true
	}
	_ = msg.NakWithDelay(retryDelay(d.maxDeliver, delivered))
	metrics.RecordConsumerDelivery(ctx, h.name, metrics.ResultRetry, time.Since(start))
	return true
}

// retryDelay picks the redelivery delay for the given delivery count from
// the capped backoff schedule. The consumer also carries the schedule as
// BackOff (governs AckWait-expiry redeliveries); the explicit NakWithDelay
// keeps handler-failure retries deterministic across server versions.
func retryDelay(maxDeliver int, delivered uint64) time.Duration {
	schedule := backoffSchedule(maxDeliver)
	idx := int(delivered) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(schedule) {
		idx = len(schedule) - 1
	}
	return schedule[idx]
}
