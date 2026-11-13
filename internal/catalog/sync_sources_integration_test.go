//go:build integration

package catalog_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
)

type mutablePuller struct {
	packages []catalog.Package
	err      error
}

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
	service := catalog.NewServiceWithSources(database, catalog.NewStore(), nil, audit.NewStore(), []catalog.SourceSync{
		{Kind: "catalog", Source: validSyncSource("broken"), Puller: broken},
		{Kind: "catalog", Source: validSyncSource("community"), Puller: good},
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
