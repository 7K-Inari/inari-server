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

func TestMatchesSelectorSubset(t *testing.T) {
	if !matchesSelector(map[string]string{"env": "prod", "region": "eu"}, map[string]string{"env": "prod"}) {
		t.Fatal("subset selector should match")
	}
	if matchesSelector(map[string]string{"env": "dev"}, map[string]string{"env": "prod"}) {
		t.Fatal("value mismatch should not match")
	}
	if matchesSelector(map[string]string{}, map[string]string{"env": "prod"}) {
		t.Fatal("missing label should not match")
	}
	if !matchesSelector(map[string]string{"env": "prod"}, map[string]string{}) {
		t.Fatal("empty selector matches everything")
	}
}

func TestResolveClusters(t *testing.T) {
	fc := &fakeClusters{clusters: []types.Cluster{
		{ID: "cluster:1", Labels: map[string]string{"env": "prod", "team": "a"}},
		{ID: "cluster:2", Labels: map[string]string{"env": "dev"}},
		{ID: "cluster:3", Labels: map[string]string{"env": "prod", "team": "b"}},
	}}
	svc := &Service{clusters: fc}
	got, err := svc.ResolveClusters(context.Background(), "org:1", map[string]string{"env": "prod", "team": "a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "cluster:1" {
		t.Fatalf("got %+v", got)
	}
}

func TestExemptionValid(t *testing.T) {
	now := time.Now()
	valid := &types.Exemption{State: types.ExemptionStateApproved, ExpiresAt: now.Add(time.Hour)}
	if !exemptionValid(valid, now) {
		t.Fatal("approved unexpired exemption should be valid")
	}
	if exemptionValid(&types.Exemption{State: types.ExemptionStatePending, ExpiresAt: now.Add(time.Hour)}, now) {
		t.Fatal("pending exemption is not valid")
	}
	if exemptionValid(&types.Exemption{State: types.ExemptionStateApproved, ExpiresAt: now.Add(-time.Hour)}, now) {
		t.Fatal("expired exemption is not valid")
	}
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
