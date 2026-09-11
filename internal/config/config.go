// Package config loads layered configuration: defaults < env (INARI_*).
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
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
	ShutdownTimeout      time.Duration

	RegistrationTokenTTL       time.Duration
	EnrollmentApprovalRequired bool
	AgentImageRepo             string
	AgentImageTag              string
	AgentGatewayAddress        string
	ESOSecretStore             string

	// Platform Vault (ESO delivery of per-cluster OIDC client secrets, plan
	// §5.3). Empty VaultAddr disables delivery; registration then fails
	// explicitly (pending_secret_delivery) instead of promising a secret
	// that never arrives.
	VaultAddr    string
	VaultToken   string
	VaultKVMount string

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
	// GitProvider selects the git backend: "fake" (default, local dev/tests)
	// or "github" (GitHub App credentials, §12.1/2 — never PATs).
	GitProvider             string
	GitHubAppID             int64
	GitHubInstallationID    int64
	GitHubAppPrivateKeyFile string

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

	// PlatformGitOpsRepo is the platform GitOps repository receiving
	// per-tenant CR manifests (tenants/<slug>/, docs/platform-gitops.md);
	// empty disables manifest commits.
	PlatformGitOpsRepo string

	// M4: Extension Host + Fleet Manager (plan §5.8, §5.11).
	// CurrentAgentVersion is the supported agent version (N); agents at N
	// and N−1 are admitted (§11/5).
	CurrentAgentVersion  string
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
		ShutdownTimeout:           durEnv("INARI_SHUTDOWN_TIMEOUT", 10*time.Second),

		RegistrationTokenTTL:       durEnv("INARI_REGISTRATION_TOKEN_TTL", time.Hour),
		EnrollmentApprovalRequired: boolEnv("INARI_ENROLLMENT_APPROVAL_REQUIRED", false),
		AgentImageRepo:             env("INARI_AGENT_IMAGE_REPO", "ghcr.io/7k-inari/inari-agent"),
		AgentImageTag:              env("INARI_AGENT_IMAGE_TAG", "edge"),
		AgentGatewayAddress:        env("INARI_AGENT_GATEWAY_ADDRESS", "https://inari-server.example.com"),
		ESOSecretStore:             env("INARI_ESO_SECRET_STORE", "inari-platform"),

		VaultAddr:    env("INARI_VAULT_ADDR", ""),
		VaultToken:   env("INARI_VAULT_TOKEN", ""),
		VaultKVMount: env("INARI_VAULT_KV_MOUNT", "secret"),

		CatalogOCIPath:          env("INARI_CATALOG_OCI_PATH", ""),
		CatalogOCIIndexRef:      env("INARI_CATALOG_OCI_INDEX_REF", ""),
		CatalogSyncInterval:     durEnv("INARI_CATALOG_SYNC_INTERVAL", 0),
		GitProvider:             env("INARI_GIT_PROVIDER", "fake"),
		GitHubAppID:             intEnv("INARI_GITHUB_APP_ID", 0),
		GitHubInstallationID:    intEnv("INARI_GITHUB_APP_INSTALLATION_ID", 0),
		GitHubAppPrivateKeyFile: env("INARI_GITHUB_APP_PRIVATE_KEY_FILE", ""),

		TZFAWSMode:           env("INARI_TZF_AWS_MODE", "fake"),
		TZFApprovalRequired:  boolEnv("INARI_TZF_APPROVAL_REQUIRED", true),
		TZFAccountQuota:      intEnv("INARI_TZF_ACCOUNT_QUOTA", 10),
		TZFAllowedRegions:    listEnv("INARI_TZF_ALLOWED_REGIONS", []string{"eu-west-1", "us-east-1"}),
		TZFAllowedTiers:      listEnv("INARI_TZF_ALLOWED_TIERS", []string{"starter"}),
		TZFRequiredTags:      listEnv("INARI_TZF_REQUIRED_TAGS", nil),
		TZFReconcileInterval: durEnv("INARI_TZF_RECONCILE_INTERVAL", 30*time.Second),
		TZFStepMaxAttempts:   intEnv("INARI_TZF_STEP_MAX_ATTEMPTS", 5),

		ScaffoldReconcileInterval: durEnv("INARI_SCAFFOLD_RECONCILE_INTERVAL", 30*time.Second),
		ScaffoldStepMaxAttempts:   intEnv("INARI_SCAFFOLD_STEP_MAX_ATTEMPTS", 5),
		ScaffoldGitOrg:            env("INARI_SCAFFOLD_GIT_ORG", ""),
		ScaffoldTemplateDir:       env("INARI_SCAFFOLD_TEMPLATE_DIR", ""),
		ScaffoldRunTTL:            durEnv("INARI_SCAFFOLD_RUN_TTL", 7*24*time.Hour),

		PlatformGitOpsRepo: env("INARI_PLATFORM_GITOPS_REPO", ""),

		CurrentAgentVersion:  env("INARI_AGENT_VERSION", ""),
		FleetAdvanceInterval: durEnv("INARI_FLEET_ADVANCE_INTERVAL", 10*time.Second),
		DriftSweepInterval:   durEnv("INARI_DRIFT_SWEEP_INTERVAL", time.Minute),

		IdentityScopes: identityScopesEnv("INARI_IDENTITY_SCOPES", DefaultIdentityScopes),
	}
	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("config: INARI_DATABASE_URL must not be empty")
	}
	if c.OIDCIssuerURL == "" {
		return nil, fmt.Errorf("config: INARI_OIDC_ISSUER_URL must not be empty")
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
