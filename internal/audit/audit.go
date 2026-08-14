// Package audit provides the append-only audit store and the transactional
// outbox: every mutation writes business rows + audit row + outbox row in one
// TX; a dispatcher delivers outbox events to registered handlers (NATS plugs
// in later behind the Publisher interface).
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// Store appends audit events and outbox rows. Implementations must accept a
// db.Querier so callers can write inside an open transaction.
type Store struct{}

func NewStore() *Store { return &Store{} }

// Record appends an audit event via q (pool or in-flight TX).
func (s *Store) Record(ctx context.Context, q db.Querier, ev *types.AuditEvent) error {
	const sql = `INSERT INTO audit_events (org_id, actor, impersonator, action, object_type, object_id, payload)
	             VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, created_at`
	var impersonator *string
	if ev.Impersonator != "" {
		impersonator = &ev.Impersonator
	}
	return q.QueryRow(ctx, sql, ev.OrgID, ev.Actor, impersonator, ev.Action, ev.ObjectType, ev.ObjectID, ev.Payload).
		Scan(&ev.ID, &ev.CreatedAt)
}

// List returns audit events for an org, newest first.
func (s *Store) List(ctx context.Context, q db.Querier, orgID string, limit int) ([]types.AuditEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	const sql = `SELECT id, org_id, actor, COALESCE(impersonator,''), action, object_type, object_id, payload, created_at
	             FROM audit_events WHERE org_id = $1 ORDER BY created_at DESC LIMIT $2`
	rows, err := q.Query(ctx, sql, orgID, limit)
	if err != nil {
		return nil, fmt.Errorf("audit: list: %w", err)
	}
	defer rows.Close()
	var out []types.AuditEvent
	for rows.Next() {
		var ev types.AuditEvent
		if err := rows.Scan(&ev.ID, &ev.OrgID, &ev.Actor, &ev.Impersonator, &ev.Action, &ev.ObjectType, &ev.ObjectID, &ev.Payload, &ev.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// AppendOutbox writes an outbox row inside the same TX as the mutation.
func AppendOutbox(ctx context.Context, q db.Querier, orgID, eventType string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("outbox: marshal: %w", err)
	}
	const sql = `INSERT INTO outbox (org_id, event_type, payload) VALUES ($1,$2,$3)`
	_, err = q.Exec(ctx, sql, orgID, eventType, raw)
	return err
}

// Handler processes one outbox event.
type Handler interface {
	EventTypes() []string
	Handle(ctx context.Context, ev *types.OutboxEvent) error
}

// HandlerFunc adapts a function to Handler for a fixed set of event types.
type HandlerFunc struct {
	Types []string
	Fn    func(ctx context.Context, ev *types.OutboxEvent) error
}

func (h HandlerFunc) EventTypes() []string { return h.Types }
func (h HandlerFunc) Handle(ctx context.Context, ev *types.OutboxEvent) error {
	return h.Fn(ctx, ev)
}

// Publisher publishes an outbox event to external consumers (NATS at M1).
// M0 runs in-process handlers only; the interface is the seam.
type Publisher interface {
	Publish(ctx context.Context, ev *types.OutboxEvent) error
}

// Dispatcher polls unpublished outbox rows and dispatches to handlers.
type Dispatcher struct {
	db       *db.DB
	handlers map[string][]Handler
	interval time.Duration
	batch    int
}

func NewDispatcher(d *db.DB, interval time.Duration, handlers ...Handler) *Dispatcher {
	if interval <= 0 {
		interval = time.Second
	}
	disp := &Dispatcher{db: d, interval: interval, batch: 100, handlers: map[string][]Handler{}}
	for _, h := range handlers {
		for _, t := range h.EventTypes() {
			disp.handlers[t] = append(disp.handlers[t], h)
		}
	}
	return disp
}

// Run polls until ctx is cancelled.
func (d *Dispatcher) Run(ctx context.Context) {
	tick := time.NewTicker(d.interval)
	defer tick.Stop()
	for {
		_ = d.DispatchOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// DispatchOnce processes one batch of unpublished events.
func (d *Dispatcher) DispatchOnce(ctx context.Context) error {
	return d.db.WithTx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, org_id, event_type, payload, occurred_at FROM outbox
			 WHERE published_at IS NULL ORDER BY id LIMIT $1 FOR UPDATE SKIP LOCKED`, d.batch)
		if err != nil {
			return fmt.Errorf("outbox: poll: %w", err)
		}
		var events []types.OutboxEvent
		for rows.Next() {
			var ev types.OutboxEvent
			if err := rows.Scan(&ev.ID, &ev.OrgID, &ev.EventType, &ev.Payload, &ev.OccurredAt); err != nil {
				rows.Close()
				return err
			}
			events = append(events, ev)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for i := range events {
			ev := &events[i]
			for _, h := range d.handlers[ev.EventType] {
				if err := h.Handle(ctx, ev); err != nil {
					return fmt.Errorf("outbox: handle %s (id %d): %w", ev.EventType, ev.ID, err)
				}
			}
			if _, err := tx.Exec(ctx, `UPDATE outbox SET published_at = now() WHERE id = $1`, ev.ID); err != nil {
				return err
			}
		}
		return nil
	})
}
