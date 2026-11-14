package orchestrator

import (
	"context"
	"errors"
	"testing"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/artifactadmission"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/types"
)

type denialCatalog struct {
	item    *types.CatalogItem
	version *types.CatalogItemVersion
}

func (d denialCatalog) GetItemByID(context.Context, string) (*types.CatalogItem, error) {
	return d.item, nil
}
func (d denialCatalog) EffectiveVersion(context.Context, string, string, string) (string, error) {
	return d.version.Version, nil
}
func (d denialCatalog) GetVersion(context.Context, string, string) (*types.CatalogItemVersion, error) {
	return d.version, nil
}
func (d denialCatalog) EnsureVisible(context.Context, string, string, string) error { return nil }
func (d denialCatalog) AdmitVersion(context.Context, string, string, trustedsource.Environment) (*catalog.AdmittedVersion, error) {
	return nil, &artifactadmission.Error{Code: artifactadmission.CodeSignatureInvalid, Err: errors.New("bad signature")}
}

type admissionCluster struct{ org string }

func (c admissionCluster) GetCluster(context.Context, string) (*types.Cluster, error) {
	return &types.Cluster{ID: "c1", OrgID: c.org, State: types.ClusterStateActive}, nil
}

func TestExternalAdmissionDenialStopsBeforeGit(t *testing.T) {
	item := &types.CatalogItem{ID: "core/web-service", SourceID: "core", Name: "web-service"}
	version := &types.CatalogItemVersion{ItemID: item.ID, Version: "1.0.0"}
	service := NewService(nil, nil, denialCatalog{item: item, version: version}, admissionCluster{org: "org:1"}, nil, nil, nil, nil)
	_, err := service.apply(context.Background(), DeployRequest{OrgID: "org:1", ClusterID: "c1", ItemID: item.ID, Version: "1.0.0"}, item, version.Version, nil)
	if !artifactadmission.IsCode(err, artifactadmission.CodeSignatureInvalid) {
		t.Fatalf("error = %v, want signature_invalid and no later git resolution", err)
	}
}
