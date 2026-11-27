package planlimits

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var meteringTokenPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

type MeteringEvent struct {
	EventID    string
	TenantID   string
	MetricName string
	Value      int64
	OccurredAt time.Time
	Attributes map[string]string
}

type MeteringEventEmitter interface {
	EmitMeteringEvent(ctx context.Context, event MeteringEvent) error
}

type NoopMeteringEmitter struct{}

func (NoopMeteringEmitter) EmitMeteringEvent(context.Context, MeteringEvent) error { return nil }

func ValidateMeteringEvent(event MeteringEvent) error {
	if event.EventID == "" || len(event.EventID) > 128 || strings.ContainsAny(event.EventID, " \t\r\n") {
		return fmt.Errorf("planlimits: invalid metering event id")
	}
	if !strings.HasPrefix(event.TenantID, "org:") || len(event.TenantID) <= len("org:") {
		return fmt.Errorf("planlimits: invalid metering tenant id")
	}
	if !meteringTokenPattern.MatchString(event.MetricName) {
		return fmt.Errorf("planlimits: invalid metering metric name")
	}
	if event.OccurredAt.IsZero() {
		return fmt.Errorf("planlimits: metering timestamp is required")
	}
	if len(event.Attributes) > 32 {
		return fmt.Errorf("planlimits: too many metering attributes")
	}
	for key, value := range event.Attributes {
		if !meteringTokenPattern.MatchString(key) || len(value) > 256 {
			return fmt.Errorf("planlimits: invalid metering attribute")
		}
	}
	return nil
}
