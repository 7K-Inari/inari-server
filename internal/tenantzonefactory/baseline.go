// Tenant-zone baseline bundle (plan §5.12 step 5): an ArgoCD Application
// installing the inari-agent from the published OCI Helm chart (with the
// one-time registration token in the values), the tenant-local ArgoCD root
// app, ESO SecretStore stub, and the baseline policy pack pointer — rendered
// into the zone's <slug>-inari-state repo.
package tenantzonefactory

import (
	"fmt"
	"sort"
	"strings"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/secrets"
	"github.com/7K-Inari/inari-server/internal/types"
)

// agentChartRepo is the OCI registry the inari-agent Helm chart is published
// to by the inari-agent release pipeline.
const agentChartRepo = "ghcr.io/7k-inari/charts"

// AgentInstallParams configure the rendered agent ArgoCD Application.
type AgentInstallParams struct {
	// ImageRepo references the published agent image from the inari-agent
	// release pipeline (never a locally built tag). The tag floats on
	// latest.
	ImageRepo string
	// GatewayAddress is the base URL agents dial out to (pull, never push).
	GatewayAddress string
	// ESO delivery wiring for the per-cluster OIDC client secret (plan
	// §5.3). When ESOSecretStore is set the chart renders an ExternalSecret
	// projecting the Vault path inari/clusters/<id>/oidc-client-secret.
	// On fresh zone clusters ESO is installed after the agent registers;
	// ArgoCD retries the sync until the CRD exists.
	ESOSecretStore     string
	ESOSecretStoreKind string
	ESOSecretName      string
	ESOSecretKey       string
}

// RenderBaseline produces the tenant-zone baseline bundle files. The ESO
// SecretStore targets Secrets Manager in the zone's own AWS account, so it
// uses the zone's region; the ArgoCD root app points at the zone repo's
// canonical clone URL from the git provider.
func RenderBaseline(cluster *types.Cluster, zone *types.TenantZone, registrationToken string, p AgentInstallParams, repoURL string) ([]gitprovider.File, error) {
	if p.ImageRepo == "" {
		return nil, fmt.Errorf("tzf: agent image repo required")
	}
	if p.GatewayAddress == "" {
		return nil, fmt.Errorf("tzf: agent gateway address required")
	}
	if p.ESOSecretStore != "" {
		if p.ESOSecretName == "" {
			p.ESOSecretName = "inari-agent-oidc-client"
		}
		if p.ESOSecretKey == "" {
			p.ESOSecretKey = "client-secret"
		}
		if p.ESOSecretStoreKind == "" {
			p.ESOSecretStoreKind = "ClusterSecretStore"
		}
	}
	app, err := renderAgentApplication(cluster, registrationToken, p)
	if err != nil {
		return nil, fmt.Errorf("tzf: baseline agent application: %w", err)
	}
	rootApp := fmt.Sprintf(`apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: inari-root
  namespace: argocd
spec:
  project: default
  source:
    repoURL: %s
    targetRevision: HEAD
    path: baseline
  destination:
    server: https://kubernetes.default.svc
    namespace: inari-system
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
`, repoURL)
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
		{Path: "baseline/inari-agent/application.yaml", Content: []byte(app)},
		{Path: "baseline/argocd/root-app.yaml", Content: []byte(rootApp)},
		{Path: "baseline/eso/secretstore.yaml", Content: []byte(eso)},
		{Path: "baseline/policy-packs/README.md", Content: []byte(policy)},
	}, nil
}

// renderAgentApplication renders the ArgoCD Application that installs the
// inari-agent from the published OCI Helm chart. The one-time registration
// token is hardcoded in the values: it is consumed once at registration, and
// on a fresh zone cluster ExternalSecrets is not installed yet. Chart and
// image float on the latest published release (targetRevision "*" resolves
// to the newest semver chart tag).
func renderAgentApplication(cluster *types.Cluster, token string, p AgentInstallParams) (string, error) {
	var b strings.Builder
	b.WriteString(`apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: inari-agent
  namespace: argocd
spec:
  project: default
  source:
    repoURL: ` + agentChartRepo + `
    chart: inari-agent
    targetRevision: "*"
    helm:
      values: |
        image:
          repository: ` + p.ImageRepo + `
          tag: latest
        config:
          tenantID: ` + cluster.OrgID + `
          controlPlane: ` + p.GatewayAddress + `
          registrationToken: ` + token + `
`)
	if labels := encodeLabels(cluster.Labels); labels != "" {
		b.WriteString("          clusterLabels: " + labels + "\n")
	}
	if p.ESOSecretStore != "" {
		b.WriteString(`        oidcSecret:
          create: true
          name: ` + p.ESOSecretName + `
          key: ` + p.ESOSecretKey + `
          secretStore: ` + p.ESOSecretStore + `
          secretStoreKind: ` + p.ESOSecretStoreKind + `
          remotePath: ` + secrets.ClusterOIDCPath(cluster.ID) + `
`)
	}
	b.WriteString(`  destination:
    server: https://kubernetes.default.svc
    namespace: inari-system
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
`)
	return b.String(), nil
}

// encodeLabels renders cluster labels as a sorted, comma-separated k=v list
// (the format the agent's INARI_CLUSTER_LABELS parser reads); empty when the
// cluster carries no labels.
func encodeLabels(labels map[string]string) string {
	pairs := make([]string, 0, len(labels))
	for k, v := range labels {
		pairs = append(pairs, k+"="+v)
	}
	sort.Strings(pairs)
	return strings.Join(pairs, ",")
}
