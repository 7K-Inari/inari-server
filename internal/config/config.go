// Package config loads layered configuration: defaults < env (INARI_*).
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blang/semver"
)

// ServiceScopes is one entry of the read-only identity scopes catalog: the
// audiences/scope names tenant OIDC clients may request (plan §5.4, Settings
// design §3.1).
type ServiceScopes struct {
	Audience string   `json:"audience"`
	Scopes   []string `json:"scopes"`
}

// DefaultIdentityScopes is the built-in scopes catalog used when
// INARI_IDENTITY_SCOPES is unset.
var DefaultIdentityScopes = []ServiceScopes{
	{Audience: "inari-server", Scopes: []string{"read", "write"}},
	{Audience: "inari-agent-gateway", Scopes: []string{"connect"}},
	{Audience: "inari-catalog", Scopes: []string{"read", "deploy"}},
	// kubectl access via kubelogin (plan §5.4, §7.2): the per-tenant
	// org-<slug>-kubectl client requests this audience.
	{Audience: "kubernetes", Scopes: []string{"cluster"}},
}

type Config struct {
	HTTPAddr             string
	LogLevel             string
	LogFormat            string
	DatabaseURL          string
	OIDCIssuerURL        string
	OIDCClientID         string
	KeycloakBaseURL      string
	KeycloakRealm        string
	KeycloakClientID     string
	KeycloakClientSecret string
	OpenFGAAPIURL        string
	OpenFGAStoreName     string
	// PlatformAdminGroup is the Keycloak realm group whose members receive
	// platform:inari org_creator tuples (M1; path relative to realm root).
	PlatformAdminGroup string
	// PlatformGroupSyncInterval is the platform group → tuple reconciliation
	// period; it bounds the consistency window for grants/revocations.
	PlatformGroupSyncInterval time.Duration
	// OrgGroupSyncInterval is the org team group → tuple reconciliation
	// period (ADR-0004); it bounds the convergence window for IdP-brokered
	// managed members.
	OrgGroupSyncInterval time.Duration
	OutboxPollInterval   time.Duration
	// NATSURL is the (possibly comma-separated) NATS endpoint list backing
	// the event bus (ADR-0014). REQUIRED — the server refuses to boot
	// without it: the outbox relay publishes to JetStream and handlers are
	// delivered via per-handler durable consumer groups.
	NATSURL string
	// NATSStreamReplicas is the JetStream replica count for the INARI_OUTBOX
	// stream (1 for a single-node bus, 3 for a clustered one).
	NATSStreamReplicas int
	ShutdownTimeout    time.Duration
	// LeaderLeaseTTL is the leader-lease validity period (ADR-0011): it
	// bounds failover of the gated singleton loops when a replica dies
	// without releasing. Renewal runs at TTL/3.
	LeaderLeaseTTL time.Duration

	// Cache layer (internal/cache; ADR-0010): CacheBackend selects "memory"
	// (default, in-process) or "redis" (shared, requires RedisURL). Backs the
	// OpenFGA PEP cache (CachePEPTTL, spike-mandated 1-5s) and the tenant
	// slug→org cache (CacheTenantTTL). All cache failures are fail-open.
	CacheBackend string
	RedisURL     string
	CachePEPTTL  time.Duration
	// CacheTenantTTL bounds staleness of the slug→org cache when the memory
	// backend runs multi-replica (invalidation is process-local there).
	CacheTenantTTL        time.Duration
	CacheMemoryMaxEntries int

	RegistrationTokenTTL       time.Duration
	EnrollmentApprovalRequired bool
	AgentImageRepo             string
	AgentGatewayAddress        string
	// ExtensionGatewayAudience is the audience scope pinned on per-extension
	// Keycloak service-account clients and enforced by the extension-gateway
	// tunnel validator (ADR-0008): only client_credentials JWTs minted for an
	// ext-<name> client with this audience may invoke actions. The interim
	// shared INARI_EXTENSION_GATEWAY_TOKEN was removed (issue #75).
	ExtensionGatewayAudience string
	ESOSecretStore           string

	// Platform Vault (ESO delivery of per-cluster OIDC client secrets, plan
	// §5.3). Empty VaultAddr disables delivery; registration then fails
	// explicitly (pending_secret_delivery) instead of promising a secret
	// that never arrives.
	VaultAddr    string
	VaultToken   string
	VaultKVMount string
	// VaultAuthMethod selects how the server authenticates to Vault:
	// "token" (static VaultToken, default/back-compat) or "kubernetes"
	// (ServiceAccount JWT login, short-lived tokens, no secret material to
	// distribute or rotate).
	VaultAuthMethod string
	// VaultK8sRole is the Vault Kubernetes-auth role bound to the
	// inari-server ServiceAccount (policy: update on
	// <VaultKVMount>/data/inari/clusters/* only).
	VaultK8sRole string
	// VaultK8sAuthPath is the Vault auth mount for the Kubernetes method
	// (default "kubernetes"); VaultK8sTokenPath overrides the SA JWT path
	// (default the in-pod ServiceAccount token).
	VaultK8sAuthPath  string
	VaultK8sTokenPath string

	// CatalogOCIPath points at a local fixture OCI layout directory
	// (dev/tests). CatalogOCIIndexRef takes precedence when both are set.
	CatalogOCIPath string
	// CatalogOCIIndexRef is the OCI reference of the inari-catalog index
	// artifact (e.g. ghcr.io/7k-inari/catalog/index:latest). When set, the
	// real registry puller is used instead of the fixture.
	CatalogOCIIndexRef string
	// CatalogSyncInterval re-syncs the catalog periodically; 0 = sync once
	// at startup only.
	CatalogSyncInterval time.Duration
	// GitProvider selects the git backend: "fake" (default, local dev/tests),
	// "github" (GitHub App credentials, §12.1/2 — never PATs), or "local"
	// (filesystem-backed bare repos under GitLocalRoot — real commits for
	// dev/e2e environments without a git host).
	GitProvider             string
	GitLocalRoot            string
	GitHubAppID             int64
	GitHubAppPrivateKeyFile string
	// GitHubInstallationID is DEPRECATED (pinned single-org installs); the
	// platform app's installation is now resolved per tenant at runtime.
	// When set it seeds the installation cache for back-compat.
	GitHubInstallationID int64
	// GitHubAPIBase is the platform app's API base ("": github.com; or a
	// GHE https://<host>/api/v3).
	GitHubAPIBase string
	// GitHubAppSlug builds tenant install links (<web>/apps/<slug>/installations/new).
	GitHubAppSlug         string
	GitHubInstallCacheTTL time.Duration
	// GitHubAllowedAPIBases allowlists tenant BYO apiBase hosts (empty: any https host).
	GitHubAllowedAPIBases []string
	// TenantGitKeyMountRoot is where ESO renders tenant BYO app keys.
	TenantGitKeyMountRoot string

	// User git connections (W4: per-user git social login). UserGitEnabled
	// gates the whole module; the dedicated GitHub user-OAuth app (client
	// id + mounted secret file — never an inline secret) is distinct from
	// the platform/BYO installation apps above.
	UserGitEnabled                bool
	UserGitGitHubClientID         string
	UserGitGitHubClientSecretFile string
	UserGitGitHubScopes           string
	// UserGitCallbackURL is the public callback URL registered on the app.
	UserGitCallbackURL string
	// UserGitUIReturnURL is where the callback redirects the browser.
	UserGitUIReturnURL string
	// UserGitAPIBaseAllowlist allowlists GHE/self-hosted API base URLs
	// (empty: github.com only).
	UserGitAPIBaseAllowlist []string
	// UserGitKEKBackend selects the DEK-wrapping KEK: "static" (AES-256-GCM
	// key file, dev default) or "transit" (OpenBao/Vault transit engine).
	UserGitKEKBackend       string
	UserGitTransitAddr      string
	UserGitTransitMount     string
	UserGitTransitKeyName   string
	UserGitTransitTokenFile string
	// UserGitStateKeyFile holds the HMAC key signing OAuth states; empty
	// derives it from the GitHub client secret.
	UserGitStateKeyFile    string
	UserGitStateTTL        time.Duration
	UserGitAccessCacheSkew time.Duration

	// Tenant Zone Factory (plan §5.12). TZFAWSMode selects the AWS backend:
	// "fake" (default; deterministic in-memory — the M3 acceptance layer)
	// or "aws" (SDK against a real dev organization when credentials exist).
	TZFAWSMode           string
	TZFApprovalRequired  bool
	TZFAccountQuota      int64
	TZFAllowedRegions    []string
	TZFAllowedTiers      []string
	TZFRequiredTags      []string
	TZFReconcileInterval time.Duration
	TZFStepMaxAttempts   int64

	// Scaffolding / Software Templates (M8, plan §4/§10).
	// ScaffoldGitOrg is the git organization/owner receiving scaffolded
	// repos; ScaffoldTemplateDir is the local dir holding template
	// definitions; ScaffoldRunTTL is the retention for completed/failed
	// runs before they are swept.
	ScaffoldReconcileInterval time.Duration
	ScaffoldStepMaxAttempts   int64
	ScaffoldGitOrg            string
	ScaffoldTemplateDir       string
	ScaffoldRunTTL            time.Duration
	// ScaffoldTemplateOCIIndexRef switches template ingestion from the
	// local dir to the OCI registry index (application/vnd.inari.template.v1
	// artifacts); ScaffoldTemplateCacheDir receives the extracted packages.
	ScaffoldTemplateOCIIndexRef string
	ScaffoldTemplateCacheDir    string
	// ScaffoldTemplateVerify enables cosign keyless signature verification
	// of template artifacts (same trust model as the server images).
	ScaffoldTemplateVerify         bool
	ScaffoldTemplateCosignIdentity string
	ScaffoldTemplateCosignIssuer   string

	// UiExtensionVerify enables cosign keyless signature verification of
	// UI-extension remoteEntry OCI artifacts before the control plane serves
	// them (§5.8/§5.10). Identity/issuer regexps pin the signing workflow.
	UiExtensionVerify         bool
	UiExtensionCosignIdentity string
	UiExtensionCosignIssuer   string

	// PlatformGitOpsRepo is the platform GitOps repository receiving
	// per-tenant CR manifests (tenants/<slug>/, docs/platform-gitops.md);
	// empty disables manifest commits.
	PlatformGitOpsRepo string

	// GitStateRepoOrg is the git owner (org/user) owning the per-tenant
	// <slug>-inari-state repos. Providers that require owner-qualified
	// repos (github) fail on the bare convention; when set, the RBAC
	// materializer's fallback target becomes <org>/<slug>-inari-state.
	// Empty keeps the bare name (fake/local providers).
	GitStateRepoOrg string

	// M4: Extension Host + Fleet Manager (plan §5.8, §5.11).
	// CurrentAgentVersion is the supported agent version (N); agents at N
	// and N−1 are admitted (§11/5). Legacy fallback policy, superseded by
	// AgentSupportedRange when that is set.
	CurrentAgentVersion string
	// AgentSupportedRange is the platform-declared semver range of
	// supported inari-agent versions (e.g. ">=0.5.0 <0.6.0", sourced from
	// the inari-platform chart's agent.supportedRange via the
	// inari-agent-compat ConfigMap). When set, the handshake skew check
	// evaluates reported versions against this range; when empty, the
	// legacy N/N−1 policy against CurrentAgentVersion applies unchanged.
	AgentSupportedRange string
	// AgentRecommendedVersion is the exact agent version the platform
	// recommends for installs/upgrades (inari-platform agent.recommended).
	// Advertised to agents in the handshake response, surfaced through the
	// cluster registry API, and used to pin Tenant Zone Factory install
	// manifests. Empty means "no recommendation" (installs float latest).
	AgentRecommendedVersion string
	// AgentFloatLatest is the dev escape hatch: even with
	// AgentRecommendedVersion set, TZF install manifests float on
	// "targetRevision: *" / "image.tag: latest".
	AgentFloatLatest     bool
	FleetAdvanceInterval time.Duration
	DriftSweepInterval   time.Duration

	// IdentityScopes is the read-only catalog of per-service audiences/scopes
	// served at GET /tenants/{org}/identity/scopes (Settings design §3.1).
	IdentityScopes []ServiceScopes
}

func Load() (*Config, error) {
	c := &Config{
		HTTPAddr:                  env("INARI_HTTP_ADDR", ":8080"),
		LogLevel:                  env("INARI_LOG_LEVEL", "info"),
		LogFormat:                 env("INARI_LOG_FORMAT", "json"),
		DatabaseURL:               env("INARI_DATABASE_URL", "postgres://inari:inari@localhost:5432/inari?sslmode=disable"),
		OIDCIssuerURL:             env("INARI_OIDC_ISSUER_URL", "http://localhost:8081/realms/inari"),
		OIDCClientID:              env("INARI_OIDC_CLIENT_ID", "inari-server"),
		KeycloakBaseURL:           env("INARI_KEYCLOAK_BASE_URL", "http://localhost:8081"),
		KeycloakRealm:             env("INARI_KEYCLOAK_REALM", "inari"),
		KeycloakClientID:          env("INARI_KEYCLOAK_CLIENT_ID", "inari-platform-admin"),
		KeycloakClientSecret:      env("INARI_KEYCLOAK_CLIENT_SECRET", ""),
		OpenFGAAPIURL:             env("INARI_OPENFGA_API_URL", "http://localhost:8082"),
		OpenFGAStoreName:          env("INARI_OPENFGA_STORE_NAME", "inari"),
		PlatformAdminGroup:        env("INARI_PLATFORM_ADMIN_GROUP", "platform-admins"),
		PlatformGroupSyncInterval: durEnv("INARI_PLATFORM_GROUP_SYNC_INTERVAL", 30*time.Second),
		OrgGroupSyncInterval:      durEnv("INARI_ORG_GROUP_SYNC_INTERVAL", 30*time.Second),
		OutboxPollInterval:        durEnv("INARI_OUTBOX_POLL_INTERVAL", time.Second),
		NATSURL:                   env("INARI_NATS_URL", ""),
		NATSStreamReplicas:        int(intEnv("INARI_NATS_STREAM_REPLICAS", 1)),
		ShutdownTimeout:           durEnv("INARI_SHUTDOWN_TIMEOUT", 10*time.Second),
		LeaderLeaseTTL:            durEnv("INARI_LEADER_LEASE_TTL", 10*time.Second),

		CacheBackend:          env("INARI_CACHE_BACKEND", "memory"),
		RedisURL:              env("INARI_REDIS_URL", "redis://localhost:6379/0"),
		CachePEPTTL:           durEnv("INARI_CACHE_PEP_TTL", 2*time.Second),
		CacheTenantTTL:        durEnv("INARI_CACHE_TENANT_TTL", 10*time.Second),
		CacheMemoryMaxEntries: int(intEnv("INARI_CACHE_MEMORY_MAX_ENTRIES", 10000)),

		RegistrationTokenTTL:       durEnv("INARI_REGISTRATION_TOKEN_TTL", time.Hour),
		EnrollmentApprovalRequired: boolEnv("INARI_ENROLLMENT_APPROVAL_REQUIRED", false),
		AgentImageRepo:             env("INARI_AGENT_IMAGE_REPO", "ghcr.io/7k-inari/inari-agent"),
		AgentGatewayAddress:        env("INARI_AGENT_GATEWAY_ADDRESS", "https://inari-server.example.com"),
		ExtensionGatewayAudience:   env("INARI_EXTENSION_GATEWAY_AUDIENCE", "inari-extension-gateway"),
		ESOSecretStore:             env("INARI_ESO_SECRET_STORE", "inari-platform"),

		VaultAddr:        env("INARI_VAULT_ADDR", ""),
		VaultToken:       env("INARI_VAULT_TOKEN", ""),
		VaultKVMount:     env("INARI_VAULT_KV_MOUNT", "secret"),
		VaultAuthMethod:  env("INARI_VAULT_AUTH_METHOD", "token"),
		VaultK8sRole:     env("INARI_VAULT_K8S_ROLE", ""),
		VaultK8sAuthPath: env("INARI_VAULT_K8S_AUTH_PATH", ""),
		VaultK8sTokenPath: env("INARI_VAULT_K8S_TOKEN_PATH",
			"/var/run/secrets/kubernetes.io/serviceaccount/token"),

		CatalogOCIPath:          env("INARI_CATALOG_OCI_PATH", ""),
		CatalogOCIIndexRef:      env("INARI_CATALOG_OCI_INDEX_REF", ""),
		CatalogSyncInterval:     durEnv("INARI_CATALOG_SYNC_INTERVAL", 0),
		GitProvider:             env("INARI_GIT_PROVIDER", "fake"),
		GitLocalRoot:            env("INARI_GIT_LOCAL_ROOT", "/var/lib/inari/git"),
		GitHubAppID:             intEnv("INARI_GITHUB_APP_ID", 0),
		GitHubInstallationID:    intEnv("INARI_GITHUB_APP_INSTALLATION_ID", 0),
		GitHubAppPrivateKeyFile: env("INARI_GITHUB_APP_PRIVATE_KEY_FILE", ""),
		GitHubAPIBase:           env("INARI_GITHUB_API_BASE", ""),
		GitHubAppSlug:           env("INARI_GITHUB_APP_SLUG", ""),
		GitHubInstallCacheTTL:   durEnv("INARI_GITHUB_INSTALL_CACHE_TTL", 5*time.Minute),
		GitHubAllowedAPIBases:   listEnv("INARI_GITHUB_ALLOWED_API_BASES", nil),
		TenantGitKeyMountRoot:   env("INARI_TENANT_GIT_KEY_MOUNT_ROOT", "/var/run/inari/tenant-git-keys"),

		UserGitEnabled:                boolEnv("INARI_USERGIT_ENABLED", false),
		UserGitGitHubClientID:         env("INARI_USERGIT_GITHUB_CLIENT_ID", ""),
		UserGitGitHubClientSecretFile: env("INARI_USERGIT_GITHUB_CLIENT_SECRET_FILE", ""),
		UserGitGitHubScopes:           env("INARI_USERGIT_GITHUB_SCOPES", "repo read:user"),
		UserGitCallbackURL:            env("INARI_USERGIT_CALLBACK_URL", ""),
		UserGitUIReturnURL:            env("INARI_USERGIT_UI_RETURN_URL", "/settings/git"),
		UserGitAPIBaseAllowlist:       listEnv("INARI_USERGIT_API_BASE_ALLOWLIST", nil),
		UserGitKEKBackend:             env("INARI_USERGIT_KEK_BACKEND", "static"),
		UserGitTransitAddr:            env("INARI_USERGIT_TRANSIT_ADDR", ""),
		UserGitTransitMount:           env("INARI_USERGIT_TRANSIT_MOUNT", "transit"),
		UserGitTransitKeyName:         env("INARI_USERGIT_TRANSIT_KEY_NAME", "inari-usergit"),
		UserGitTransitTokenFile:       env("INARI_USERGIT_TRANSIT_TOKEN_FILE", ""),
		UserGitStateKeyFile:           env("INARI_USERGIT_STATE_KEY_FILE", ""),
		UserGitStateTTL:               durEnv("INARI_USERGIT_STATE_TTL", 10*time.Minute),
		UserGitAccessCacheSkew:        durEnv("INARI_USERGIT_ACCESS_CACHE_SKEW", time.Minute),

		TZFAWSMode:           env("INARI_TZF_AWS_MODE", "fake"),
		TZFApprovalRequired:  boolEnv("INARI_TZF_APPROVAL_REQUIRED", true),
		TZFAccountQuota:      intEnv("INARI_TZF_ACCOUNT_QUOTA", 10),
		TZFAllowedRegions:    listEnv("INARI_TZF_ALLOWED_REGIONS", []string{"eu-west-1", "us-east-1"}),
		TZFAllowedTiers:      listEnv("INARI_TZF_ALLOWED_TIERS", []string{"starter"}),
		TZFRequiredTags:      listEnv("INARI_TZF_REQUIRED_TAGS", nil),
		TZFReconcileInterval: durEnv("INARI_TZF_RECONCILE_INTERVAL", 30*time.Second),
		TZFStepMaxAttempts:   intEnv("INARI_TZF_STEP_MAX_ATTEMPTS", 5),

		ScaffoldReconcileInterval:      durEnv("INARI_SCAFFOLD_RECONCILE_INTERVAL", 30*time.Second),
		ScaffoldStepMaxAttempts:        intEnv("INARI_SCAFFOLD_STEP_MAX_ATTEMPTS", 5),
		ScaffoldGitOrg:                 env("INARI_SCAFFOLD_GIT_ORG", ""),
		ScaffoldTemplateDir:            env("INARI_SCAFFOLD_TEMPLATE_DIR", ""),
		ScaffoldRunTTL:                 durEnv("INARI_SCAFFOLD_RUN_TTL", 7*24*time.Hour),
		ScaffoldTemplateOCIIndexRef:    env("INARI_SCAFFOLD_TEMPLATE_OCI_INDEX_REF", ""),
		ScaffoldTemplateCacheDir:       env("INARI_SCAFFOLD_TEMPLATE_CACHE_DIR", ""),
		ScaffoldTemplateVerify:         boolEnv("INARI_SCAFFOLD_TEMPLATE_VERIFY", false),
		ScaffoldTemplateCosignIdentity: env("INARI_SCAFFOLD_TEMPLATE_COSIGN_IDENTITY", ""),
		ScaffoldTemplateCosignIssuer:   env("INARI_SCAFFOLD_TEMPLATE_COSIGN_ISSUER", ""),

		UiExtensionVerify:         boolEnv("INARI_UI_EXTENSION_VERIFY", false),
		UiExtensionCosignIdentity: env("INARI_UI_EXTENSION_COSIGN_IDENTITY", ""),
		UiExtensionCosignIssuer:   env("INARI_UI_EXTENSION_COSIGN_ISSUER", ""),

		PlatformGitOpsRepo: env("INARI_PLATFORM_GITOPS_REPO", ""),
		GitStateRepoOrg:    env("INARI_GIT_STATE_REPO_ORG", ""),

		CurrentAgentVersion:     env("INARI_AGENT_VERSION", ""),
		AgentSupportedRange:     env("INARI_AGENT_SUPPORTED_RANGE", ""),
		AgentRecommendedVersion: env("INARI_AGENT_RECOMMENDED_VERSION", ""),
		AgentFloatLatest:        boolEnv("INARI_AGENT_FLOAT_LATEST", false),
		FleetAdvanceInterval:    durEnv("INARI_FLEET_ADVANCE_INTERVAL", 10*time.Second),
		DriftSweepInterval:      durEnv("INARI_DRIFT_SWEEP_INTERVAL", time.Minute),

		IdentityScopes: identityScopesEnv("INARI_IDENTITY_SCOPES", DefaultIdentityScopes),
	}
	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("config: INARI_DATABASE_URL must not be empty")
	}
	if c.OIDCIssuerURL == "" {
		return nil, fmt.Errorf("config: INARI_OIDC_ISSUER_URL must not be empty")
	}
	if c.NATSURL == "" {
		return nil, fmt.Errorf("config: INARI_NATS_URL must not be empty (ADR-0014: the event bus is obligatory)")
	}
	if c.AgentSupportedRange != "" {
		if _, err := semver.ParseRange(c.AgentSupportedRange); err != nil {
			return nil, fmt.Errorf("config: INARI_AGENT_SUPPORTED_RANGE %q is not a valid semver range: %w", c.AgentSupportedRange, err)
		}
	}
	if c.NATSStreamReplicas < 1 {
		return nil, fmt.Errorf("config: INARI_NATS_STREAM_REPLICAS must be >= 1, got %d", c.NATSStreamReplicas)
	}
	if c.CacheBackend != "memory" && c.CacheBackend != "redis" {
		return nil, fmt.Errorf("config: INARI_CACHE_BACKEND must be \"memory\" or \"redis\", got %q", c.CacheBackend)
	}
	// TTLs must be positive: both backends treat ttl <= 0 as "never expire",
	// which would silently disable the documented staleness bound.
	if c.CachePEPTTL <= 0 {
		return nil, fmt.Errorf("config: INARI_CACHE_PEP_TTL must be positive (1-5s recommended), got %s", c.CachePEPTTL)
	}
	if c.CacheTenantTTL <= 0 {
		return nil, fmt.Errorf("config: INARI_CACHE_TENANT_TTL must be positive, got %s", c.CacheTenantTTL)
	}
	if c.UserGitKEKBackend != "static" && c.UserGitKEKBackend != "transit" {
		return nil, fmt.Errorf("config: INARI_USERGIT_KEK_BACKEND must be \"static\" or \"transit\", got %q", c.UserGitKEKBackend)
	}
	if c.UserGitKEKBackend == "transit" {
		if c.UserGitTransitAddr == "" || c.UserGitTransitTokenFile == "" || c.UserGitTransitKeyName == "" {
			return nil, fmt.Errorf("config: transit KEK requires INARI_USERGIT_TRANSIT_ADDR, INARI_USERGIT_TRANSIT_TOKEN_FILE and INARI_USERGIT_TRANSIT_KEY_NAME")
		}
	}
	if c.UserGitEnabled {
		if c.UserGitGitHubClientID == "" || c.UserGitGitHubClientSecretFile == "" {
			return nil, fmt.Errorf("config: INARI_USERGIT_ENABLED requires INARI_USERGIT_GITHUB_CLIENT_ID and INARI_USERGIT_GITHUB_CLIENT_SECRET_FILE")
		}
		if c.UserGitCallbackURL == "" {
			return nil, fmt.Errorf("config: INARI_USERGIT_ENABLED requires INARI_USERGIT_CALLBACK_URL")
		}
	}
	return c, nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func durEnv(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(n) * time.Second
	}
	return def
}

func boolEnv(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func intEnv(key string, def int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return def
	}
	return n
}

// listEnv reads a comma-separated list; empty means the default.
func listEnv(key string, def []string) []string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// identityScopesEnv reads the scopes catalog as JSON
// ([{audience, scopes: []}]); empty or invalid means the default.
func identityScopesEnv(key string, def []ServiceScopes) []ServiceScopes {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	var out []ServiceScopes
	if err := json.Unmarshal([]byte(v), &out); err != nil || len(out) == 0 {
		return def
	}
	return out
}
