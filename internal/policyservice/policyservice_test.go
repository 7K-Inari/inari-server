package policyservice

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/types"
)

type fakeClusters struct {
	clusters []types.Cluster
	byID     map[string]*types.Cluster
}

func (f *fakeClusters) ListClusters(context.Context, string) ([]types.Cluster, error) {
	return f.clusters, nil
}

func (f *fakeClusters) GetCluster(_ context.Context, id string) (*types.Cluster, error) {
	if c, ok := f.byID[id]; ok {
		return c, nil
	}
	return nil, errors.New("unknown cluster")
}

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
