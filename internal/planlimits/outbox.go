package planlimits

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
)

const EventMeteringRecorded = "metering.recorded"

type MeteringEventPayload struct {
	EventID    string            `json:"eventId"`
	OrgID      string            `json:"orgId"`
	MetricName string            `json:"metricName"`
	Value      int64             `json:"value"`
	OccurredAt time.Time         `json:"occurredAt"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type OutboxEmitter struct {
	database *db.DB
}

func NewOutboxEmitter(database *db.DB) *OutboxEmitter {
	return &OutboxEmitter{database: database}
}

func (e *OutboxEmitter) EmitMeteringEvent(ctx context.Context, event MeteringEvent) error {
	if err := ValidateMeteringEvent(event); err != nil {
		return err
	}
	if e == nil || e.database == nil {
		return fmt.Errorf("planlimits: outbox database is not configured")
	}
	payload := MeteringEventPayload{
		EventID: event.EventID, OrgID: event.TenantID, MetricName: event.MetricName,
		Value: event.Value, OccurredAt: event.OccurredAt, Attributes: event.Attributes,
	}
	return e.database.WithTx(ctx, func(tx pgx.Tx) error {
		return audit.AppendOutbox(ctx, tx, event.TenantID, EventMeteringRecorded, payload)
	})
}
