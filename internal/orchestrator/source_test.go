package orchestrator

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

const sourceTestDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type sourceCatalog struct {
	version *types.CatalogItemVersion
}

func (c sourceCatalog) GetVersion(context.Context, string, string) (*types.CatalogItemVersion, error) {
	return c.version, nil
}
func (c sourceCatalog) GetItemByID(context.Context, string) (*types.CatalogItem, error) {
	return nil, nil
}
func (c sourceCatalog) EffectiveVersion(_ context.Context, _, _, _ string) (string, error) {
	return c.version.Version, nil
}
func (c sourceCatalog) EnsureVisible(context.Context, string, string, string) error { return nil }

func TestSourceDescriptorUsesExactHelmDigest(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{
		"admission": map[string]any{"type": "platform-app"},
		"chart":     map[string]any{"repoURL": "oci://ghcr.io/7k-hiroba/payments-api/charts", "chart": "payments-api", "digest": sourceTestDigest},
	})
	svc := NewService(nil, nil, nil, nil, nil, nil, nil, nil)
	svc.catalog = sourceCatalog{version: &types.CatalogItemVersion{Version: "1.4.0", Payload: payload}}
	desc, helm, err := svc.sourceDescriptor(context.Background(), DeployRequest{ItemID: "hiroba/payments-api", Spec: json.RawMessage(`{"replicas":2}`)}, "1.4.0")
	if err != nil {
		t.Fatal(err)
	}
	if !helm || desc.Kind != types.SourceKindHelm || desc.Helm.Digest != sourceTestDigest || desc.Helm.Version != "1.4.0" {
		t.Fatalf("descriptor = %#v, helm=%v", desc, helm)
	}
}

func TestSourceDescriptorKeepsKROPath(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, nil, nil, nil)
	svc.catalog = sourceCatalog{version: &types.CatalogItemVersion{Payload: json.RawMessage(`{"admission":{"type":"kro-rgd"}}`)}}
	desc, helm, err := svc.sourceDescriptor(context.Background(), DeployRequest{ItemID: "core/postgresql"}, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if helm || desc.Kind != types.SourceKindKRO || !strings.Contains(desc.KRO.RGDRef, "core/postgresql@1.0.0") {
		t.Fatalf("descriptor = %#v, helm=%v", desc, helm)
	}
}
