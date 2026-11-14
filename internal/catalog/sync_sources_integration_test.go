//go:build integration

package catalog_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
	"github.com/7K-Inari/inari-server/internal/types"
)

type mutablePuller struct {
	packages    []catalog.Package
	err         error
	indexDigest string
}

func (p *mutablePuller) LastIndexDigest() string { return p.indexDigest }

func (p *mutablePuller) Pull(context.Context) ([]catalog.Package, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.packages, nil
}

func validSyncSource(id string) trustedsource.Source {
	return trustedsource.Source{
		ID: id, IndexRef: "ghcr.io/example/" + id + "/catalog/index:latest", TrustTier: trustedsource.TrustExperimental,
		ArtifactPrefixes: []string{"ghcr.io/example/" + id + "/"},
		Publisher: trustedsource.Publisher{
			Issuer: "https://token.actions.githubusercontent.com", Repository: "example/workflows",
			Workflows: trustedsource.DefaultArtifactWorkflows(), WorkflowSHA: "0123456789abcdef0123456789abcdef01234567",
			SourceRepository: "example/" + id, SourceWorkflow: ".github/workflows/release.yml",
		},
	}
}

func TestSyncSourcesIndependentFailuresAndLastGood(t *testing.T) {
	ctx := context.Background()
	pg, err := testutil.SharedPostgres(ctx)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	database, err := testdb.NewDatabase(t, pg)
	if err != nil {
		t.Fatal(err)
	}
	broken := &mutablePuller{err: errors.New("bad signature")}
	good := &mutablePuller{packages: []catalog.Package{{
		Name: "web-service", DisplayName: "Web service", Description: "Web service", Type: "kro-rgd", Version: "1.0.0", Channel: "stable",
		OCIRef:      "ghcr.io/example/community/catalog/web-service@sha256:" + strings.Repeat("b", 64),
		Entry:       trustedsource.IndexEntry{Digest: "sha256:" + strings.Repeat("b", 64), PackageVersion: "1.0.0"},
		IndexDigest: "sha256:" + strings.Repeat("c", 64),
	}}}
	goodSource := validSyncSource("community")
	service := catalog.NewServiceWithSources(database, catalog.NewStore(), nil, audit.NewStore(), []catalog.SourceSync{
		{Kind: "catalog", Source: validSyncSource("broken"), Puller: broken},
		{Kind: "catalog", Source: goodSource, Puller: good},
	})
	count, err := service.Sync(ctx)
	if err == nil || !strings.Contains(err.Error(), "bad signature") || count != 1 {
		t.Fatalf("Sync count/error = %d, %v", count, err)
	}
	item, err := catalog.NewStore().GetItem(ctx, database.Pool, "community/web-service")
	if err != nil || !item.SnapshotPresent {
		t.Fatalf("valid source did not commit: %+v, %v", item, err)
	}
	states, err := service.ListTrustedSourceStates(ctx, "catalog")
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]string{}
	for _, state := range states {
		byID[state.SourceID] = state.State
	}
	if byID["broken"] != "failed" || byID["community"] != "ready" {
		t.Fatalf("states = %+v", byID)
	}

	good.err = errors.New("registry unavailable")
	if _, err := service.Sync(ctx); err == nil {
		t.Fatal("expected second sync failure")
	}
	states, err = service.ListTrustedSourceStates(ctx, "catalog")
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range states {
		if state.SourceID == "community" && (state.State != "stale" || state.LastSuccessAt == nil) {
			t.Fatalf("community did not retain last-good: %+v", state)
		}
	}
	item, err = catalog.NewStore().GetItem(ctx, database.Pool, "community/web-service")
	if err != nil || !item.SnapshotPresent {
		t.Fatalf("last-good item was removed: %+v, %v", item, err)
	}
	for _, state := range states {
		if state.SourceID == "community" {
			if state.IndexRef != goodSource.IndexRef || state.TrustTier != string(goodSource.TrustTier) || state.Unsigned {
				t.Errorf("configured source metadata = %+v", state)
			}
		}
	}
	views, _, err := service.ListVisible(ctx, "org:acme", types.CatalogListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || views[0].SourceState != "stale" {
		t.Fatalf("visible source state = %+v, want stale", views)
	}

	if err := catalog.NewStore().ReconcileSourcePolicies(ctx, database.Pool, "catalog", map[string]string{"community": "sha256:" + strings.Repeat("f", 64)}); err != nil {
		t.Fatal(err)
	}
	item, err = catalog.NewStore().GetItem(ctx, database.Pool, "community/web-service")
	if err != nil || item.SnapshotPresent {
		t.Fatalf("policy change reused last-good content: %+v, %v", item, err)
	}
	states, err = service.ListTrustedSourceStates(ctx, "catalog")
	if err != nil {
		t.Fatal(err)
	}
	byID = map[string]string{}
	for _, state := range states {
		byID[state.SourceID] = state.State
	}
	if byID["community"] != "policy-changed" || byID["broken"] != "unconfigured" {
		t.Fatalf("reconciled states = %+v", byID)
	}
}

type blockingPuller struct {
	packages     []catalog.Package
	calls        atomic.Int32
	active       atomic.Int32
	maxActive    atomic.Int32
	firstStarted chan struct{}
	releaseFirst chan struct{}
}

func (p *blockingPuller) Pull(ctx context.Context) ([]catalog.Package, error) {
	p.calls.Add(1)
	active := p.active.Add(1)
	defer p.active.Add(-1)
	for {
		max := p.maxActive.Load()
		if active <= max || p.maxActive.CompareAndSwap(max, active) {
			break
		}
	}
	if p.calls.Load() == 1 {
		close(p.firstStarted)
		select {
		case <-p.releaseFirst:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return p.packages, nil
}

func TestConcurrentSourceSyncAttemptsSerialize(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pg, err := testutil.SharedPostgres(ctx)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	database, err := testdb.NewDatabase(t, pg)
	if err != nil {
		t.Fatal(err)
	}
	puller := &blockingPuller{
		packages: []catalog.Package{{
			Name: "web-service", DisplayName: "Web service", Description: "Web service", Type: "kro-rgd", Version: "1.0.0", Channel: "stable",
			OCIRef: "ghcr.io/example/community/catalog/web-service@sha256:" + strings.Repeat("b", 64),
			Entry:  trustedsource.IndexEntry{Digest: "sha256:" + strings.Repeat("b", 64), PackageVersion: "1.0.0"}, IndexDigest: "sha256:" + strings.Repeat("c", 64),
		}},
		firstStarted: make(chan struct{}), releaseFirst: make(chan struct{}),
	}
	source := validSyncSource("community")
	service := catalog.NewServiceWithSources(database, catalog.NewStore(), nil, audit.NewStore(), []catalog.SourceSync{{Kind: "catalog", Source: source, Puller: puller}})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := service.SyncKind(ctx, "catalog")
		errs <- err
	}()
	<-puller.firstStarted
	go func() {
		defer wg.Done()
		_, err := service.SyncKind(ctx, "catalog")
		errs <- err
	}()
	select {
	case <-time.After(200 * time.Millisecond):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if calls := puller.calls.Load(); calls != 1 {
		t.Errorf("second source attempt started before the first released the source lock (calls=%d)", calls)
	}
	close(puller.releaseFirst)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if max := puller.maxActive.Load(); max != 1 {
		t.Fatalf("maximum concurrent pulls = %d, want 1", max)
	}
	states, err := service.ListTrustedSourceStates(ctx, "catalog")
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].Generation != 2 || states[0].State != "ready" {
		t.Fatalf("source status after concurrent attempts = %+v", states)
	}
}

func TestEmptySourceSnapshotRetainsVerifiedIndexDigest(t *testing.T) {
	ctx := context.Background()
	pg, err := testutil.SharedPostgres(ctx)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	database, err := testdb.NewDatabase(t, pg)
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("d", 64)
	source := validSyncSource("empty")
	puller := &mutablePuller{indexDigest: digest}
	service := catalog.NewServiceWithSources(database, catalog.NewStore(), nil, audit.NewStore(), []catalog.SourceSync{{Kind: "catalog", Source: source, Puller: puller}})
	if count, err := service.Sync(ctx); err != nil || count != 0 {
		t.Fatalf("empty Sync count/error = %d, %v", count, err)
	}
	states, err := service.ListTrustedSourceStates(ctx, "catalog")
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].State != "ready" || states[0].ItemCount != 0 || states[0].LastGoodIndexDigest != digest {
		t.Fatalf("empty source status = %+v", states)
	}
}
