//go:build integration

package catalog_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
	"github.com/7K-Inari/inari-server/internal/types"
	"github.com/jackc/pgx/v5"
)

func replacementFor(sourceID, digest, channel string) catalog.SourceReplacement {
	source := trustedsource.Source{ID: sourceID, TrustTier: trustedsource.TrustReviewed}
	itemID := sourceID + "/web-service"
	return catalog.SourceReplacement{
		Kind: "catalog", Source: source, Fingerprint: "sha256:" + strings.Repeat("a", 64),
		Items:            []*types.CatalogItem{{ID: itemID, Source: types.CatalogSourceCurated, SourceID: sourceID, TrustTier: string(source.TrustTier), Name: "web-service", DisplayName: "Web service", SourceFingerprint: "sha256:" + strings.Repeat("a", 64), SnapshotPresent: true}},
		Versions:         []*types.CatalogItemVersion{{ItemID: itemID, Version: "1.0.0", PackageVersion: "1.0.0", Channel: channel, ArtifactRef: "ghcr.io/example/web-service@" + digest, ArtifactDigest: digest, SnapshotPresent: true}},
		LastGoodIndexRef: "ghcr.io/example/index:latest", IndexDigest: digest,
		Now: time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC),
	}
}

func TestReplaceSourceAtomicLastGoodAndIndependentIdentity(t *testing.T) {
	ctx := context.Background()
	pg, err := testutil.SharedPostgres(ctx)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	database, err := testdb.NewDatabase(t, pg)
	if err != nil {
		t.Fatal(err)
	}
	store := catalog.NewStore()
	a := replacementFor("core", "sha256:"+strings.Repeat("a", 64), "stable")
	b := replacementFor("community", "sha256:"+strings.Repeat("b", 64), "incubating")
	if err := database.WithTx(ctx, func(tx pgx.Tx) error { return store.ReplaceSource(ctx, tx, a) }); err != nil {
		t.Fatal(err)
	}
	if err := database.WithTx(ctx, func(tx pgx.Tx) error { return store.ReplaceSource(ctx, tx, b) }); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ id, channel string }{{"core/web-service", "stable"}, {"community/web-service", "incubating"}} {
		item, err := store.GetItem(ctx, database.Pool, tc.id)
		if err != nil || !item.SnapshotPresent {
			t.Fatalf("GetItem(%s) = %+v, %v", tc.id, item, err)
		}
		versions, err := store.ListVersions(ctx, database.Pool, tc.id)
		if err != nil || len(versions) != 1 || versions[0].Channel != tc.channel {
			t.Fatalf("ListVersions(%s) = %+v, %v", tc.id, versions, err)
		}
	}

	changed := replacementFor("core", "sha256:"+strings.Repeat("c", 64), "stable")
	if err := database.WithTx(ctx, func(tx pgx.Tx) error { return store.ReplaceSource(ctx, tx, changed) }); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("error = %v, want immutable digest rejection", err)
	}
	versions, err := store.ListVersions(ctx, database.Pool, "core/web-service")
	if err != nil || len(versions) != 1 || versions[0].ArtifactDigest != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("failed replacement changed last-good: %+v, %v", versions, err)
	}
	communityVersions, err := store.ListVersions(ctx, database.Pool, "community/web-service")
	if err != nil || len(communityVersions) != 1 || communityVersions[0].Channel != "incubating" {
		t.Fatalf("independent source was touched: %+v, %v", communityVersions, err)
	}

	now := time.Date(2026, 11, 13, 12, 30, 0, 0, time.UTC)
	if err := store.RecordSourceFailure(ctx, database.Pool, "catalog", a.Source, a.Fingerprint, "digest_mismatch", errImmutableForTest, now); err != nil {
		t.Fatal(err)
	}
	states, err := catalog.NewStore().ListTrustedSourceStates(ctx, database.Pool, "catalog", now)
	if err != nil || len(states) != 2 {
		t.Fatalf("states = %+v, %v", states, err)
	}
	byID := map[string]types.TrustedSourceStatus{}
	for _, state := range states {
		byID[state.SourceID] = state
	}
	if byID["core"].State != "stale" || byID["core"].Generation != 1 || byID["core"].LastSuccessAt == nil || byID["core"].SnapshotAgeSeconds != 1800 || byID["core"].LastErrorCode != "digest_mismatch" {
		t.Fatalf("core status = %+v", byID["core"])
	}
	if byID["community"].State != "ready" {
		t.Fatalf("community status = %+v", byID["community"])
	}
}

var errImmutableForTest = errors.New("same-version digest changed")
