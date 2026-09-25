package metrics

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHandlerExposesInstruments(t *testing.T) {
	h, shutdown, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	defer func() { _ = shutdown(ctx) }()

	RecordCacheOp(ctx, CachePEP, "memory", OpGet, ResultHit)
	RecordCacheOp(ctx, CachePEP, "memory", OpGet, ResultMiss)
	RecordCacheOp(ctx, CacheTenant, "redis", OpGet, ResultError)
	RecordInvalidation(ctx, CachePEP)
	ObserveFGACheck(ctx, 5*time.Millisecond, ResultAllowed, false)
	ObserveFGACheck(ctx, time.Millisecond, ResultDenied, true)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()

	for _, want := range []string{
		`inari_cache_operations_total{`,
		`cache="pep"`,
		`cache="tenant"`,
		`backend="memory"`,
		`op="get"`,
		`result="hit"`,
		`inari_cache_invalidations_total{`,
		`inari_fga_check_duration_seconds`,
		`inari_fga_check_total{`,
		`cached="true"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics body missing %q\nbody:\n%s", want, body)
		}
	}
}
