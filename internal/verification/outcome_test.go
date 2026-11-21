package verification_test

import (
	"strings"
	"testing"
	"time"

	verification "github.com/7K-Inari/inari-server/internal/verification"
)

func TestParseGenericOutcome(t *testing.T) {
	now := time.Date(2026, 11, 21, 1, 0, 0, 0, time.UTC)
	valid := `{"schema":"inari.verification.outcome/v1","result":"passed","checks":[{"name":"api","state":"passed"}],"expiresAt":"2026-11-21T02:00:00Z"}`
	got, expiry, err := verification.ParseGenericOutcome([]byte(valid), 65536, now)
	if err != nil || got == nil || got.Result != "passed" || !expiry.After(now) {
		t.Fatalf("valid outcome = %#v, %s, %v", got, expiry, err)
	}
	tests := []string{
		`{"schema":"inari.verification.outcome/v1","result":"passed","expiresAt":"2026-11-21T02:00:00Z","url":"https://attacker"}`,
		`{"schema":"inari.verification.outcome/v1","result":"passed","checks":[{"name":"api","state":"failed"}],"expiresAt":"2026-11-21T02:00:00Z"}`,
		`{"schema":"inari.verification.outcome/v1","result":"passed","expiresAt":"2026-11-21T00:30:00Z"}`,
		`{"schema":"other","result":"passed","expiresAt":"2026-11-21T02:00:00Z"}`,
	}
	for _, raw := range tests {
		if _, _, err := verification.ParseGenericOutcome([]byte(raw), 65536, now); err == nil {
			t.Errorf("invalid outcome accepted: %s", raw)
		}
	}
	if _, _, err := verification.ParseGenericOutcome([]byte(strings.Repeat("x", 100)), 99, now); err == nil {
		t.Fatal("oversized outcome accepted")
	}
}
