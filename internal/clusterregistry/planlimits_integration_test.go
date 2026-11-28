//go:build integration

package clusterregistry

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/7K-Inari/inari-server/internal/planlimits"
)

type staticPlanLimits struct{ limits planlimits.Limits }

func (p staticPlanLimits) PlanLimits(context.Context, string) (planlimits.Limits, error) {
	return p.limits, nil
}

func TestClusterLimitHTTPErrorAndExistingUsage(t *testing.T) {
	srv, svc, _ := itServerDB(t, itAuthorizer{allow: true})
	defer srv.Close()
	one := int64(1)
	svc.WithPlanLimitsProvider(staticPlanLimits{limits: planlimits.Limits{MaxClusters: &one}})
	itCreate(t, srv, "acme", "within-cap")

	code, body := itReq(t, srv, http.MethodPost, "/api/v1/tenants/acme/clusters", "good", `{"name":"over-cap"}`)
	if code != http.StatusTooManyRequests {
		t.Fatalf("over-cap create = %d %s, want 429", code, body)
	}
	var payload struct {
		Code         string `json:"code"`
		Limit        string `json:"limit"`
		CurrentUsage int64  `json:"currentUsage"`
		MaxAllowed   int64  `json:"maxAllowed"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Code != "plan_limit_exceeded" || payload.Limit != planlimits.LimitClusters || payload.CurrentUsage != 1 || payload.MaxAllowed != 1 {
		t.Fatalf("error payload = %+v", payload)
	}

	var denied *planlimits.LimitExceededError
	_, err := svc.CreateCluster(context.Background(), "user-1", "org:1", "another", nil)
	if !errors.As(err, &denied) {
		t.Fatalf("service denial = %T %v", err, err)
	}
}

func TestClusterLimitConcurrentCreatesCannotExceedCap(t *testing.T) {
	_, svc, _ := itServerDB(t, itAuthorizer{allow: true})
	two := int64(2)
	svc.WithPlanLimitsProvider(staticPlanLimits{limits: planlimits.Limits{MaxClusters: &two}})

	const attempts = 6
	var wg sync.WaitGroup
	errs := make(chan error, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := svc.CreateCluster(context.Background(), "user-1", "org:1", "cluster-"+string(rune('a'+i)), nil)
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	created := 0
	for err := range errs {
		if err == nil {
			created++
			continue
		}
		var denied *planlimits.LimitExceededError
		if !errors.As(err, &denied) {
			t.Fatalf("unexpected create error: %v", err)
		}
	}
	if created != 2 {
		t.Fatalf("created = %d, want exactly 2", created)
	}
	clusters, err := svc.ListClusters(context.Background(), "org:1")
	if err != nil || len(clusters) != 2 {
		t.Fatalf("persisted clusters = %d, %v", len(clusters), err)
	}
}
