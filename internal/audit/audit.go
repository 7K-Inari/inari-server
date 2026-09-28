// Package audit provides the append-only audit store and the transactional
// outbox: every mutation writes business rows + audit row + outbox row in one
// TX. Outbox rows are relayed to the JetStream stream INARI_OUTBOX
// (inari.outbox.<event-type>) and delivered to per-handler durable consumer
// groups (see nats.go, ADR-0014); the Postgres outbox table stays the
// transactional write side and the replay source of truth.
package audit

import (
	"context"
	"encoding/json"
	"fmt"

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
	return s.ListFiltered(ctx, q, orgID, EventFilter{Limit: limit})
}

// EventFilter narrows an audit listing; empty fields match everything.
// From/To are RFC3339 bounds on created_at (inclusive).
type EventFilter struct {
	Action     string
	Actor      string
	ObjectType string
	From       string
	To         string
	Limit      int
}

// ListFiltered returns audit events for an org matching f, newest first.
func (s *Store) ListFiltered(ctx context.Context, q db.Querier, orgID string, f EventFilter) ([]types.AuditEvent, error) {
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	const sql = `SELECT id, org_id, actor, COALESCE(impersonator,''), action, object_type, object_id, payload, created_at
	             FROM audit_events
	             WHERE org_id = $1
	               AND ($2 = '' OR action = $2)
	               AND ($3 = '' OR actor = $3)
	               AND ($4 = '' OR object_type = $4)
	               AND ($5 = '' OR created_at >= $5::timestamptz)
	               AND ($6 = '' OR created_at <= $6::timestamptz)
	             ORDER BY created_at DESC LIMIT $7`
	rows, err := q.Query(ctx, sql, orgID, f.Action, f.Actor, f.ObjectType, f.From, f.To, limit)
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

// Publisher publishes an outbox event to external consumers. Implemented by
// NATSPublisher (nats.go) over JetStream (ADR-0014).
type Publisher interface {
	Publish(ctx context.Context, ev *types.OutboxEvent) error
}
