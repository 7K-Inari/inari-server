package orchestrator

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/7K-Inari/inari-server/internal/renderer"
	"github.com/7K-Inari/inari-server/internal/types"
)

// RepoPath is the deterministic location of an instance's manifests in the
// tenant state repo: clusters/<cluster>/<item>/<instance>/.
func RepoPath(clusterID, itemID, instanceID string) string {
	return fmt.Sprintf("clusters/%s/%s/%s", clusterID, strings.TrimPrefix(itemID, "curated:"), instanceID)
}

// RenderInstanceManifest renders a deploy spec into a KRO instance manifest.
// Back-compat wrapper: the implementation lives in the source-agnostic
// renderer (kro handler); this adapts the catalog-version payload shape.
// Instance deploys keep prune-on via RenderArgoCDApplication below.
func RenderInstanceManifest(ver *types.CatalogItemVersion, name, namespace string, spec json.RawMessage) ([]byte, error) {
	var payload struct {
		RGD string `json:"rgd"`
	}
	if err := json.Unmarshal(ver.Payload, &payload); err != nil {
		return nil, fmt.Errorf("orchestrator: parse version payload: %w", err)
	}
	return renderer.RenderKROInstance([]byte(payload.RGD), name, namespace, spec)
}

// ApplicationParams describes the ArgoCD Application to render.
type ApplicationParams struct {
	Name           string
	Project        string
	RepoURL        string
	Path           string
	TargetRevision string
	DestNamespace  string
}

// RenderArgoCDApplication renders the tenant-local ArgoCD Application that
// reconciles an instance path in the tenant state repo. Back-compat wrapper
// over the renderer's git-path Application builder; instance deploys keep
// their historical prune-on sync policy (decision 2's prune-off default
// applies to the addon adoption path, not existing instance deploys).
func RenderArgoCDApplication(p ApplicationParams) []byte {
	return renderer.RenderSingleClusterApplication(renderer.RenderParams{
		Name:       p.Name,
		ID:         p.Name, // empty AppPrefix → name verbatim
		Project:    p.Project,
		RepoURL:    p.RepoURL,
		Path:       p.Path,
		BaseBranch: p.TargetRevision,
		Namespace:  p.DestNamespace,
		Prune:      true,
	})
}
