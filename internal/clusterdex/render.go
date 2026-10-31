package clusterdex

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/7K-Inari/inari-server/internal/secrets"
)

// AppName derives the per-cluster Dex Application/release name — a direct
// port of the operator's tenantChildName("dex", clusterID): "dex-<id>",
// truncated with a short content hash past 63 chars so the name stays a
// valid DNS-1123 label (it doubles as the Helm fullnameOverride, pinning
// the Service DNS name the default issuer URL derives from). The server's
// typed cluster IDs carry a "cluster:" prefix, which is not DNS-safe and
// is trimmed first.
func AppName(clusterID string) string {
	s := "dex-" + strings.TrimPrefix(clusterID, "cluster:")
	const maxName = 63
	if len(s) <= maxName {
		return s
	}
	sum := sha256.Sum256([]byte(s))
	suffix := hex.EncodeToString(sum[:])[:8]
	truncated := strings.TrimRight(s[:maxName-len(suffix)-1], "-.")
	return truncated + "-" + suffix
}

// DefaultIssuerURL derives the deterministic cluster-local Dex issuer
// (operator parity): ArgoCD is configured against this issuer only — never
// against platform Keycloak directly (ADR-0012).
func DefaultIssuerURL(clusterID string) string {
	return fmt.Sprintf("http://%s.dex.svc.cluster.local:5556/dex", AppName(clusterID))
}

// splitImageRef splits a full image reference into repository and tag
// (ported from the operator). Digest references are rejected: they would
// split into an invalid repository:tag pair.
func splitImageRef(image string) (repository, tag string, err error) {
	if strings.Contains(image, "@") {
		return "", "", fmt.Errorf("image %q must use an explicit tag, digest references are not supported", image)
	}
	idx := strings.LastIndex(image, ":")
	if idx < 0 || idx < strings.LastIndex(image, "/") {
		return "", "", fmt.Errorf("image %q must include an explicit tag", image)
	}
	return image[:idx], image[idx+1:], nil
}

// dexBaseValues builds the cluster-invariant hardened Helm values for the
// upstream dex chart (operator parity: dexHelmValues minus the per-cluster
// fullnameOverride/configSecret, which live in the per-cluster overlay).
// Secret material is referenced by name/key only — never embedded.
func dexBaseValues(cfg Config) (map[string]any, error) {
	values := map[string]any{
		"commonLabels": map[string]any{
			"app.kubernetes.io/part-of": partOfLabel,
		},
		"service": map[string]any{
			"ports": map[string]any{
				"http": map[string]any{"port": dexServicePort},
			},
		},
		// Default-deny egress except DNS and 443 (Keycloak issuer). The
		// upstream chart's ingress rule is port-scoped.
		"networkPolicy": map[string]any{
			"enabled": true,
			"egressRules": []any{
				map[string]any{
					"to": []any{
						map[string]any{
							"namespaceSelector": map[string]any{
								"matchLabels": map[string]any{"kubernetes.io/metadata.name": "kube-system"},
							},
						},
					},
					"ports": []any{
						map[string]any{"port": 53, "protocol": "UDP"},
						map[string]any{"port": 53, "protocol": "TCP"},
					},
				},
				map[string]any{
					"to": []any{
						map[string]any{"ipBlock": map[string]any{"cidr": "0.0.0.0/0"}},
					},
					"ports": []any{
						map[string]any{"port": 443, "protocol": "TCP"},
					},
				},
			},
		},
		"podDisruptionBudget": map[string]any{
			"enabled":      true,
			"minAvailable": 1,
		},
		"podSecurityContext": map[string]any{
			"runAsNonRoot":   true,
			"runAsUser":      1001,
			"runAsGroup":     1001,
			"fsGroup":        1001,
			"seccompProfile": map[string]any{"type": "RuntimeDefault"},
		},
		"securityContext": map[string]any{
			"allowPrivilegeEscalation": false,
			"readOnlyRootFilesystem":   true,
			"capabilities":             map[string]any{"drop": []any{"ALL"}},
		},
		"resources": map[string]any{
			"requests": map[string]any{"cpu": "50m", "memory": "64Mi"},
			"limits":   map[string]any{"memory": "128Mi"},
		},
	}
	if cfg.DexImage != "" {
		repo, tag, err := splitImageRef(cfg.DexImage)
		if err != nil {
			return nil, err
		}
		values["image"] = map[string]any{"repository": repo, "tag": tag}
	}
	return values, nil
}

// dexOverlay builds the per-cluster Dex values (renderer overlay convention:
// clusters/<cluster>/<name>/values.yaml): the fullnameOverride pins the
// Service name so the deterministic issuer stays valid; the full config.yaml
// comes from the ESO/Vault-synced Secret (configSecret.create=false).
func dexOverlay(clusterID string) (map[string]any, error) {
	return map[string]any{
		"fullnameOverride": AppName(clusterID),
		"configSecret": map[string]any{
			"create": false,
			"name":   DexConfigSecretName,
		},
	}, nil
}

// RBACGroups is the ArgoCD group mapping derived from the tenant's teams:
// admin-role teams map to role:admin, every other team to role:readonly
// (fail-closed policyDefault "" is the chart default; the ClusterDex CR
// took these as explicit lists — the selector-model replacement derives
// them from the team structure so they cannot drift from it).
type RBACGroups struct {
	Admin  []string
	Viewer []string
}

// TeamRef is the tenancy seam the derivation needs (team role + Keycloak
// group path, e.g. /tenant-acme/platform-team — the rbacmaterialize
// contract).
type TeamRef struct {
	RoleName  string
	GroupPath string
}

// RBACGroupsFromTeams derives the admin/viewer group lists, sorted for
// deterministic output. Newline injection is rejected (operator parity: a
// group string must never inject extra policy.csv lines).
func RBACGroupsFromTeams(teams []TeamRef) (RBACGroups, error) {
	var g RBACGroups
	for _, t := range teams {
		if t.GroupPath == "" {
			continue
		}
		if strings.ContainsAny(t.GroupPath, "\r\n") {
			return RBACGroups{}, fmt.Errorf("argocd group %q must be a single line", t.GroupPath)
		}
		if t.RoleName == "admin" {
			g.Admin = append(g.Admin, t.GroupPath)
		} else {
			g.Viewer = append(g.Viewer, t.GroupPath)
		}
	}
	sort.Strings(g.Admin)
	sort.Strings(g.Viewer)
	return g, nil
}

// argoConfigBaseValues builds the cluster-invariant values for the
// argocd-config appset: the inari-platform chart renders ONLY its argocd
// section (the hub-side postgres/keycloak sections stay off).
func argoConfigBaseValues(cfg Config) map[string]any {
	return map[string]any{
		"postgresql": map[string]any{"enabled": false},
		"keycloak":   map[string]any{"enabled": false},
		"argocd": map[string]any{
			"enabled":   true,
			"namespace": cfg.argoCDNamespace(),
		},
	}
}

// argoConfigOverlay builds the per-cluster argocd-config values: the OIDC
// issuer/secret reference (cluster-local Dex), the team-derived RBAC group
// mapping, and the ESO wiring projecting the cluster's Vault path. Secret
// values are never embedded — only names, keys, and the Vault path.
func argoConfigOverlay(cfg Config, clusterID, _ string, groups RBACGroups) ([]byte, error) {
	argo := map[string]any{
		"oidc": map[string]any{
			"issuerUrl": DefaultIssuerURL(clusterID),
			"clientSecretRef": map[string]any{
				"name": ArgoCDClientSecretName,
				"key":  ArgoCDClientSecretKey,
			},
		},
		"rbac": map[string]any{
			"policyDefault": "",
			"adminGroups":   groups.Admin,
			"viewerGroups":  groups.Viewer,
		},
	}
	if cfg.ESOSecretStore != "" {
		argo["secrets"] = map[string]any{
			"enabled":             true,
			"secretStore":         cfg.ESOSecretStore,
			"secretStoreKind":     cfg.esoSecretStoreKind(),
			"vaultPath":           secrets.ClusterOIDCPath(clusterID),
			"dexConfigSecretName": DexConfigSecretName,
			"dexNamespace":        DexNamespace,
		}
	}
	return yaml.Marshal(map[string]any{"argocd": argo})
}

// yamlMarshal marshals one values overlay document.
func yamlMarshal(v map[string]any) ([]byte, error) {
	return yaml.Marshal(v)
}

// DexConfigInput carries the material for the per-cluster Dex config.yaml.
// This is the ONLY artifact that embeds secret material, and it is written
// to the platform Vault (ESO delivery) at registration — never to git.
type DexConfigInput struct {
	// Issuer is the cluster-local Dex issuer (default: DefaultIssuerURL).
	Issuer string
	// KeycloakIssuerURL is the platform Keycloak issuer the Dex OIDC
	// connector federates against.
	KeycloakIssuerURL string
	// ClientID / ClientSecret are the cluster-<id>-dex client credentials.
	ClientID     string
	ClientSecret string
	// ArgoCDStaticSecret is the Dex static-client secret ArgoCD
	// authenticates with (server-generated at registration).
	ArgoCDStaticSecret string
}

// RenderDexConfig renders the full Dex config.yaml (operator contract:
// Keycloak OIDC connector with scopes openid profile email groups
// organization + getUserInfo, static client "argocd", enablePasswordDB
// break-glass). The output goes to Vault; it is never committed.
func RenderDexConfig(in DexConfigInput) ([]byte, error) {
	if in.Issuer == "" || in.KeycloakIssuerURL == "" || in.ClientID == "" {
		return nil, fmt.Errorf("clusterdex: dex config requires issuer, keycloak issuer and client id")
	}
	doc := map[string]any{
		"issuer": in.Issuer,
		"storage": map[string]any{
			"type":   "kubernetes",
			"config": map[string]any{"inCluster": true},
		},
		"web": map[string]any{
			"http": fmt.Sprintf("0.0.0.0:%d", dexServicePort),
		},
		"oauth2":           map[string]any{"skipApprovalScreen": true},
		"enablePasswordDB": true,
		"connectors": []any{
			map[string]any{
				"type": "oidc",
				"id":   "keycloak",
				"name": "Keycloak",
				"config": map[string]any{
					"issuer":       in.KeycloakIssuerURL,
					"clientID":     in.ClientID,
					"clientSecret": in.ClientSecret,
					"redirectURI":  strings.TrimRight(in.Issuer, "/") + "/callback",
					"getUserInfo":  true,
					"scopes":       []any{"openid", "profile", "email", "groups", "organization"},
					"claimMapping": map[string]any{"groups": "groups"},
				},
			},
		},
		"staticClients": []any{
			map[string]any{
				"id":           argoCDClientID,
				"name":         argoCDStaticName,
				"secret":       in.ArgoCDStaticSecret,
				"redirectURIs": []any{argoCDRedirect},
			},
		},
	}
	return yaml.Marshal(doc)
}
