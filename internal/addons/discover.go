// Discovery ingest (Feature C, plan §6 "Discovery"): the agent's addon
// scanner reports helm releases matched against the known-addon list; the
// server upserts cluster_addons rows with state=discovered, never
// overwriting managed rows (the store's UpsertDiscoveredAddon enforces it).
package addons

import (
	"context"
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// ReportAddonsEventType is the agent→server event type carrying discovered
// addons on the status stream. The pinned agent contract has no ReportAddons
// message yet (proto mod lands with the agent milestone); until then the
// payload is a structpb.Struct bridge decoded by DecodeReportAddons:
//
//	{"addons": [{"catalogItem": "platform:cert-manager", "releaseName": "cert-manager",
//	             "namespace": "cert-manager", "detectedVersion": "v1.16.2",
//	             "chart": "cert-manager", "repoUrl": "https://charts.jetstack.io"}]}
//
// Unknown/malformed payloads are drop-and-log per the stream compatibility
// contract; the generated message replaces the bridge without a wire change
// to the event type string.
const ReportAddonsEventType = "EVENT_TYPE_REPORT_ADDONS"

// DiscoveredAddon is one scanner-reported helm release matched to a catalog
// addon item.
type DiscoveredAddon struct {
	CatalogItem     string `json:"catalogItem"`
	ReleaseName     string `json:"releaseName,omitempty"`
	Namespace       string `json:"namespace,omitempty"`
	DetectedVersion string `json:"detectedVersion,omitempty"`
	Chart           string `json:"chart,omitempty"`
	RepoURL         string `json:"repoUrl,omitempty"`
}

// DecodeReportAddons decodes the structpb bridge payload. It returns an
// error for payloads that are not the expected Struct shape (drop-and-log
// at the caller).
func DecodeReportAddons(payload *anypb.Any) ([]DiscoveredAddon, error) {
	if payload == nil || !payload.MessageIs(&structpb.Struct{}) {
		return nil, fmt.Errorf("addons: report-addons payload is not a struct")
	}
	var doc structpb.Struct
	if err := payload.UnmarshalTo(&doc); err != nil {
		return nil, fmt.Errorf("addons: decode report-addons: %w", err)
	}
	raw, err := doc.MarshalJSON()
	if err != nil {
		return nil, err
	}
	var report struct {
		Addons []DiscoveredAddon `json:"addons"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("addons: decode report-addons items: %w", err)
	}
	return report.Addons, nil
}

// IngestDiscovery upserts scanner-reported addons as state=discovered.
// Items whose catalog item is unknown are skipped (the scanner matches
// against the platform-app catalog, so unknowns indicate drift), as are
// items the org already manages fleet-wide (a managed '*' row absorbs
// per-cluster sightings — plan §6 "never overwriting managed rows",
// extended to not re-creating them). One TX per batch; a single audit row
// records the ingest.
func (s *Service) IngestDiscovery(ctx context.Context, orgID, clusterID string, items []DiscoveredAddon) error {
	if len(items) == 0 {
		return nil
	}
	ingested := 0
	err := s.inTx(ctx, func(q db.Querier) error {
		for _, item := range items {
			if item.CatalogItem == "" {
				continue
			}
			if _, err := s.catalog.GetItemByID(ctx, item.CatalogItem); err != nil {
				continue // unknown catalog item: skip
			}
			// Fleet-managed item: the '*' row owns the item org-wide;
			// per-cluster sightings were absorbed at adopt time.
			if fleet, err := s.store.GetClusterAddon(ctx, q, orgID, "*", item.CatalogItem); err == nil &&
				fleet.State != types.AddonStateDiscovered {
				continue
			}
			meta, err := json.Marshal(item)
			if err != nil {
				return err
			}
			row := &types.ClusterAddon{
				OrgID: orgID, ClusterID: clusterID, CatalogItem: item.CatalogItem,
				State:      types.AddonStateDiscovered,
				DeployMode: types.AddonDeployModeApplication,
				Source: types.SourceDescriptor{
					Kind: types.SourceKindHelm,
					Helm: &types.HelmSource{RepoURL: item.RepoURL, Chart: item.Chart, Version: item.DetectedVersion},
				},
				ChartVersion:   item.DetectedVersion,
				DiscoveredMeta: meta,
			}
			if err := s.store.UpsertDiscoveredAddon(ctx, q, row); err != nil {
				return err
			}
			ingested++
		}
		if ingested == 0 {
			return nil
		}
		return s.recordAudit(ctx, q, orgID, "agent:"+clusterID, "addon.discovered", clusterID, map[string]any{
			"cluster": clusterID, "reported": len(items), "ingested": ingested,
		})
	})
	if err != nil {
		return fmt.Errorf("addons: ingest discovery: %w", err)
	}
	return nil
}
