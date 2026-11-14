//go:build integration

package scaffold

import (
	"context"
	"encoding/json"
	"testing"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
)

func TestTrustedTemplateSyncPersistsManifest(t *testing.T) {
	source := setupTrustedTemplateRegistry(t, testTemplateYAML+"scaffold:\n  requiresApproval: true\n")
	source.Source.ID = "core"
	source.Source.Publisher = trustedsource.Publisher{
		Issuer: "https://token.actions.githubusercontent.com", Repository: "example/workflows",
		Workflows: trustedsource.DefaultArtifactWorkflows(), WorkflowSHA: "0123456789abcdef0123456789abcdef01234567",
		SourceRepository: "example/templates", SourceWorkflow: ".github/workflows/release.yml",
	}
	ctx := context.Background()
	pg, err := testutil.SharedPostgres(ctx)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	database, err := testdb.NewDatabase(t, pg)
	if err != nil {
		t.Fatal(err)
	}
	service := catalog.NewServiceWithSources(database, catalog.NewStore(), nil, audit.NewStore(), []catalog.SourceSync{{
		Kind: "template", Source: source.Source, Puller: CatalogTemplatePuller{source},
	}})
	if count, err := service.SyncKind(ctx, "template"); err != nil || count != 1 {
		t.Fatalf("SyncKind count/error = %d, %v; want one verified template", count, err)
	}
	item, err := catalog.NewStore().GetItem(ctx, database.Pool, "core/go-service")
	if err != nil {
		t.Fatal(err)
	}
	versions, err := catalog.NewStore().ListVersions(ctx, database.Pool, item.ID)
	if err != nil || len(versions) != 1 {
		t.Fatalf("versions = %+v, %v", versions, err)
	}
	var payload struct {
		Manifest struct {
			Scaffold struct {
				RequiresApproval bool `json:"requiresApproval"`
			} `json:"scaffold"`
		} `json:"manifest"`
	}
	if err := json.Unmarshal(versions[0].Payload, &payload); err != nil {
		t.Fatalf("persisted template payload is not valid JSON: %v", err)
	}
	if !payload.Manifest.Scaffold.RequiresApproval {
		t.Fatalf("persisted manifest lost requiresApproval: %s", versions[0].Payload)
	}
}
