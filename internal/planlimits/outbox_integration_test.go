//go:build integration

package planlimits_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/planlimits"
	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
)

func TestOutboxEmitterPersistsGenericEvent(t *testing.T) {
	ctx := context.Background()
	pg, err := testutil.SharedPostgres(ctx)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	database, err := testdb.NewDatabase(t, pg)
	if err != nil {
		t.Fatal(err)
	}
	emitter := planlimits.NewOutboxEmitter(database)
	now := time.Now().UTC().Truncate(time.Microsecond)
	event := planlimits.MeteringEvent{
		EventID: "evt-1", TenantID: "org:1", MetricName: "clusters.active", Value: -1,
		OccurredAt: now, Attributes: map[string]string{"source": "test"},
	}
	if err := emitter.EmitMeteringEvent(ctx, event); err != nil {
		t.Fatal(err)
	}
	var orgID, eventType string
	var raw []byte
	if err := database.Pool.QueryRow(ctx,
		`SELECT org_id, event_type, payload FROM outbox WHERE event_type = $1`, planlimits.EventMeteringRecorded).
		Scan(&orgID, &eventType, &raw); err != nil {
		t.Fatal(err)
	}
	var payload planlimits.MeteringEventPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if orgID != event.TenantID || eventType != planlimits.EventMeteringRecorded || payload.EventID != event.EventID || payload.Value != -1 || payload.Attributes["source"] != "test" {
		t.Fatalf("unexpected outbox event: %q %q %+v", orgID, eventType, payload)
	}
	invalid := event
	invalid.MetricName = "bad metric"
	if err := emitter.EmitMeteringEvent(ctx, invalid); err == nil {
		t.Fatal("invalid event reached outbox")
	}
}
