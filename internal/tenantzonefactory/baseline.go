// Tenant-zone baseline bundle (plan §5.12 step 5): inari-agent install
// manifest (embedding the one-time registration token), the tenant-local
// ArgoCD root app, ESO SecretStore stub, and the baseline policy pack
// pointer — rendered into the zone's <slug>-inari-state repo.
package tenantzonefactory

import (
	"fmt"

	"github.com/7K-Inari/inari-server/internal/clusterregistry"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// RenderBaseline produces the tenant-zone baseline bundle files. The ESO
// SecretStore targets Secrets Manager in the zone's own AWS account, so it
// uses the zone's region.
func RenderBaseline(cluster *types.Cluster, zone *types.TenantZone, registrationToken string, mp clusterregistry.ManifestParams) ([]gitprovider.File, error) {
	manifest, err := clusterregistry.RenderInstallManifest(cluster, registrationToken, mp)
	if err != nil {
		return nil, fmt.Errorf("tzf: baseline agent manifest: %w", err)
	}
	rootApp := fmt.Sprintf(`apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: inari-root
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://example.invalid/%s-inari-state.git
    targetRevision: HEAD
    path: baseline
  destination:
    server: https://kubernetes.default.svc
    namespace: inari-system
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
`, cluster.Name)
	eso := fmt.Sprintf(`apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: inari-tenant
  namespace: inari-system
spec:
  provider:
    aws:
      service: SecretsManager
      region: %s
`, zone.Region)
	policy := `# Inari baseline policy packs
# Distributed fleet-wide by the Policy Service (plan §5.11):
#   - baseline-security
#   - cost-guardrails
`
	return []gitprovider.File{
		{Path: "baseline/inari-agent/install.yaml", Content: manifest},
		{Path: "baseline/argocd/root-app.yaml", Content: []byte(rootApp)},
		{Path: "baseline/eso/secretstore.yaml", Content: []byte(eso)},
		{Path: "baseline/policy-packs/README.md", Content: []byte(policy)},
	}, nil
}
