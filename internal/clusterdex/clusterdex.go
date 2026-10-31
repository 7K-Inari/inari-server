// Package clusterdex renders the per-cluster Dex SSO baseline (operator
// sunset Phase 2, parent plan decision D5): the ClusterDex CR/controller is
// replaced by a server-rendered ArgoCD ApplicationSet pair — dex (official
// dexidp chart, pinned) and argocd-config (charts/inari-platform argocd
// section, promoted to baseline) — fanned out per baseline repo by a LIST
// generator over Inari inventory cluster labels. Membership is evaluated
// server-side (never ArgoCD cluster-secret labels), keeping the selector
// model engine-agnostic (Flux/Fleet possible later without selector
// changes).
//
// Triggers (outbox, ADR-0014): cluster.registered covers both registration
// and label changes (labels only mutate via re-registration);
// cluster.deleted drains; team/rbac events re-derive the ArgoCD group
// mapping; git.webhook.pr_merged closes the deferred-registration loop on
// pull_request-policy repos.
//
// Faithful ClusterDex reproduction (inari-operator
// internal/controller/clusterdex_application.go): hardened Dex values,
// fail-closed ArgoCD RBAC, admin/viewer Keycloak group mapping derived from
// tenant teams, secrets referenced only — never read into git, logs, or
// status. The per-cluster OIDC client (cluster-<id>-dex) and the Dex
// config.yaml material stay on the server-side provisioning seam
// (agentgateway registration → platform Vault → ESO), unchanged.
package clusterdex

const (
	// DexChartRepoURL is the official dexidp Helm chart repository (the
	// Application is single-source; the chart is never wrapped).
	DexChartRepoURL = "https://charts.dexidp.io"
	// DexChartName is the upstream chart name.
	DexChartName = "dex"
	// DefaultDexChartVersion pins the upstream chart (operator CRD default;
	// bumped deliberately).
	DefaultDexChartVersion = "0.25.2"

	// DexNamespace is the destination namespace of the Dex release.
	DexNamespace = "dex"
	// ArgoCDNamespace is where ArgoCD and its baseline ConfigMaps live.
	ArgoCDNamespace = "argocd"
	// dexServicePort is the stable Dex API port siblings rely on (also the
	// upstream chart default).
	dexServicePort = 5556

	// DisabledLabel opts a cluster out of the Dex baseline when set to
	// DisabledLabelValue (engine-agnostic selector model: default-on for
	// every active/degraded org cluster, matching the ClusterDex
	// spec.enabled default).
	DisabledLabel      = "inari.io/dex"
	DisabledLabelValue = "disabled"

	// DexConfigSecretName is the ESO/Vault-synced Secret holding the full
	// Dex config.yaml (chart configSecret.create=false); referenced only.
	DexConfigSecretName = "dex-config"
	// DexConfigSecretKey is the key holding config.yaml inside that Secret.
	DexConfigSecretKey = "config.yaml"
	// ArgoCDClientSecretName is the ESO/Vault-synced Secret holding the Dex
	// static-client secret ArgoCD authenticates with ($<name>:<key>).
	ArgoCDClientSecretName = "argocd-dex-client"
	// ArgoCDClientSecretKey is the key inside that Secret.
	ArgoCDClientSecretKey = "client-secret"

	// VaultKeyDexConfigYAML / VaultKeyArgoCDClientSecret are the keys under
	// the cluster's Vault path (secrets.ClusterOIDCPath) holding the
	// registration-provisioned Dex config and the ArgoCD static-client
	// secret.
	VaultKeyDexConfigYAML      = "dex-config-yaml"
	VaultKeyArgoCDClientSecret = "dex-argocd-client-secret"

	// repoPathDex / repoPathArgoConfig are the repo-relative render roots
	// (outside baseline/, which the tenant root app syncs — the appsets are
	// delivered via the agent registration bridge, like fleet addons).
	repoPathDex        = "dex"
	repoPathArgoConfig = "argocd-config"
	workloadDex        = "dex"
	workloadArgoConfig = "argocd-config"
	appNameTplDex      = "{{dexAppName}}"
	appNameTplArgo     = "argocd-config-{{cluster}}"
	argoCDClientID     = "argocd"
	argoCDStaticName   = "ArgoCD"
	argoCDRedirect     = "http://argocd-server.argocd.svc:8080/auth/callback"
	partOfLabel        = "inari-platform"
)

// Config carries the platform pins and ESO wiring for the Dex fan-out.
type Config struct {
	// DexChartVersion pins the dexidp chart (default DefaultDexChartVersion).
	DexChartVersion string
	// PlatformChartRepoURL / PlatformChartName / PlatformChartVersion locate
	// the inari-platform chart (OCI) backing the argocd-config appset. An
	// empty PlatformChartVersion disables the argocd-config render (the dex
	// appset still renders) and is logged — the pin is human-maintained in
	// the server chart env (release-bundle), like agent.recommended.
	PlatformChartRepoURL string
	PlatformChartName    string
	PlatformChartVersion string
	// ArgoCDNamespace overrides the ArgoCD namespace (default "argocd").
	ArgoCDNamespace string
	// DexImage optionally overrides the Dex image (repository:tag; digest
	// refs rejected, operator parity).
	DexImage string
	// ESOSecretStore / ESOSecretStoreKind wire the ExternalSecrets the
	// argocd-config chart renders (platform Vault pull). Empty store = the
	// secrets block is omitted (secrets then arrive out-of-band).
	ESOSecretStore     string
	ESOSecretStoreKind string
}

func (c Config) dexChartVersion() string {
	if c.DexChartVersion != "" {
		return c.DexChartVersion
	}
	return DefaultDexChartVersion
}

func (c Config) argoCDNamespace() string {
	if c.ArgoCDNamespace != "" {
		return c.ArgoCDNamespace
	}
	return ArgoCDNamespace
}

func (c Config) esoSecretStoreKind() string {
	if c.ESOSecretStoreKind != "" {
		return c.ESOSecretStoreKind
	}
	return "ClusterSecretStore"
}
