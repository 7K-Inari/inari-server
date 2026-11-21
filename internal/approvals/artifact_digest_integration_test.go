//go:build integration

package approvals

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
	"github.com/7K-Inari/inari-server/internal/types"
)

func TestApprovalArtifactDigestRoundTrip(t *testing.T) {
	ctx := context.Background()
	pg, err := testutil.SharedPostgres(ctx)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	database, err := testdb.NewDatabase(t, pg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `
		INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ('org:1','acme','Acme','kc-1');
		INSERT INTO catalog_items (id, source, name, display_name, description, snapshot_present)
		VALUES ('core/web-service','curated','web-service','Web service','',true);
	`); err != nil {
		t.Fatal(err)
	}
	const digest = "sha256:52ccaee6d4dd272e54bfccda77738b42e1edf0e4a20c27e23f0b6c15d01aef79"
	store := NewStore(database)
	request := &types.ApprovalRequest{OrgID: "org:1", ItemID: "core/web-service", Version: "1.0.0", ClusterID: "c1", Spec: json.RawMessage(`{}`), Requester: "user:test", ArtifactDigest: digest}
	if err := store.create(ctx, database.Pool, request); err != nil {
		t.Fatal(err)
	}
	got, err := store.get(ctx, database.Pool, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ArtifactDigest != digest {
		t.Fatalf("approval artifact digest = %q, want %q", got.ArtifactDigest, digest)
	}
}
