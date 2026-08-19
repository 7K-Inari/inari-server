package cloudaccounts

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/7K-Inari/inari-server/internal/types"
)

// Cluster metadata labels used as fallback when the dedicated columns are
// empty (agent-reported before the M3 columns existed).
const (
	labelDistribution = "inari.dev/distribution"
	labelOIDCIssuer   = "inari.dev/oidc-issuer"
)

// clusterMetadata resolves distribution and OIDC issuer, preferring the
// dedicated columns and falling back to labels.
func clusterMetadata(c *types.Cluster) (distribution, issuer string) {
	distribution = c.Distribution
	if distribution == "" {
		distribution = c.Labels[labelDistribution]
	}
	issuer = c.OIDCIssuerURL
	if issuer == "" {
		issuer = c.Labels[labelOIDCIssuer]
	}
	return distribution, issuer
}

// RenderProviderConfig renders the Crossplane ProviderConfig
// (aws.upbound.io/v1beta1) for a cloud account on a given workload cluster
// (plan §5.7). Pure function.
//
// Credential source decision:
//   - tenant run context on an EKS cluster → IRSA (the provider pod's service
//     account is annotated with the role; EKS handles the web identity).
//   - tenant run context on a non-EKS cluster → WebIdentity with the
//     cluster's OIDC issuer (recorded as the inari.dev/oidc-issuer
//     annotation; the agent wires the projected token).
//   - platform run context → WebIdentity from the platform cluster issuer,
//     then an assumeRoleChain into the tenant account role (+ external ID).
func RenderProviderConfig(acct *types.CloudAccount, cluster *types.Cluster) ([]byte, error) {
	if acct == nil || cluster == nil {
		return nil, fmt.Errorf("cloudaccounts: account and cluster are required")
	}
	distribution, issuer := clusterMetadata(cluster)

	credentials := map[string]any{}
	var assumeRoleChain []any

	switch {
	case acct.RunContext == types.CloudAccountRunContextPlatform:
		if issuer == "" {
			return nil, fmt.Errorf("cloudaccounts: platform run context needs the platform cluster OIDC issuer URL (cluster %s: set oidc_issuer_url or label %s)", cluster.ID, labelOIDCIssuer)
		}
		credentials["source"] = "WebIdentity"
		entry := map[string]any{"roleARN": acct.RoleARN}
		if acct.ExternalID != "" {
			entry["externalID"] = acct.ExternalID
		}
		assumeRoleChain = []any{entry}
	case distribution == "eks":
		credentials["source"] = "IRSA"
	default:
		if issuer == "" {
			return nil, fmt.Errorf("cloudaccounts: WebIdentity source needs the cluster OIDC issuer URL (cluster %s: set oidc_issuer_url or label %s)", cluster.ID, labelOIDCIssuer)
		}
		credentials["source"] = "WebIdentity"
		webIdentity := map[string]any{"roleARN": acct.RoleARN}
		if acct.ExternalID != "" {
			webIdentity["externalID"] = acct.ExternalID
		}
		credentials["webIdentity"] = webIdentity
	}

	metadata := map[string]any{"name": "inari-" + acct.AccountID}
	if credentials["source"] == "WebIdentity" {
		metadata["annotations"] = map[string]any{labelOIDCIssuer: issuer}
	}
	spec := map[string]any{"credentials": credentials}
	if assumeRoleChain != nil {
		spec["assumeRoleChain"] = assumeRoleChain
	}
	doc := map[string]any{
		"apiVersion": "aws.upbound.io/v1beta1",
		"kind":       "ProviderConfig",
		"metadata":   metadata,
		"spec":       spec,
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("cloudaccounts: render providerconfig: %w", err)
	}
	return out, nil
}
