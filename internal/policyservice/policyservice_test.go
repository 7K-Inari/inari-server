package policyservice

import (
	"testing"
	"time"
)

func TestValidateExemptionExpiry(t *testing.T) {
	now := time.Now()
	if err := validateExemptionExpiry(now, now.Add(24*time.Hour)); err != nil {
		t.Fatalf("1 day should be allowed: %v", err)
	}
	if err := validateExemptionExpiry(now, now.Add(90*24*time.Hour)); err != nil {
		t.Fatalf("90 days should be allowed: %v", err)
	}
	if err := validateExemptionExpiry(now, now.Add(91*24*time.Hour)); err == nil {
		t.Fatal(">90 days must be rejected")
	}
	if err := validateExemptionExpiry(now, now.Add(-time.Hour)); err == nil {
		t.Fatal("past expiry must be rejected")
	}
}
