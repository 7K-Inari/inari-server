package config

import (
	"os"
	"testing"
)

// INARI_NATS_URL is required (ADR-0014); tests that exercise its absence
// override it explicitly with t.Setenv.
func TestMain(m *testing.M) {
	_ = os.Setenv("INARI_NATS_URL", "nats://localhost:4222")
	os.Exit(m.Run())
}

func TestLoadDefaults(t *testing.T) {
	t.Setenv("INARI_HTTP_ADDR", "")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.NATSURL != "nats://localhost:4222" {
		t.Errorf("NATSURL = %q, want nats://localhost:4222", c.NATSURL)
	}
	if c.NATSStreamReplicas != 1 {
		t.Errorf("NATSStreamReplicas = %d, want 1", c.NATSStreamReplicas)
	}
	if c.HTTPAddr != ":8080" {
		t.Errorf("HTTPAddr = %q, want :8080", c.HTTPAddr)
	}
	if c.KeycloakRealm != "inari" {
		t.Errorf("KeycloakRealm = %q, want inari", c.KeycloakRealm)
	}
	if c.PlatformAdminGroup != "platform-admins" {
		t.Errorf("PlatformAdminGroup = %q, want platform-admins", c.PlatformAdminGroup)
	}
	if c.PlatformGroupSyncInterval.Seconds() != 30 {
		t.Errorf("PlatformGroupSyncInterval = %v, want 30s", c.PlatformGroupSyncInterval)
	}
	if c.OrgGroupSyncInterval.Seconds() != 30 {
		t.Errorf("OrgGroupSyncInterval = %v, want 30s", c.OrgGroupSyncInterval)
	}
	if c.ScaffoldReconcileInterval.Seconds() != 30 {
		t.Errorf("ScaffoldReconcileInterval = %v, want 30s", c.ScaffoldReconcileInterval)
	}
	if c.ScaffoldStepMaxAttempts != 5 {
		t.Errorf("ScaffoldStepMaxAttempts = %d, want 5", c.ScaffoldStepMaxAttempts)
	}
	if c.ScaffoldGitOrg != "" {
		t.Errorf("ScaffoldGitOrg = %q, want empty", c.ScaffoldGitOrg)
	}
	if c.ScaffoldTemplateDir != "" {
		t.Errorf("ScaffoldTemplateDir = %q, want empty", c.ScaffoldTemplateDir)
	}
	if c.ScaffoldRunTTL.Hours() != 168 {
		t.Errorf("ScaffoldRunTTL = %v, want 168h", c.ScaffoldRunTTL)
	}
	if c.LeaderLeaseTTL.Seconds() != 10 {
		t.Errorf("LeaderLeaseTTL = %v, want 10s", c.LeaderLeaseTTL)
	}
}

func TestLoadEnvOverride(t *testing.T) {
	t.Setenv("INARI_HTTP_ADDR", ":9090")
	t.Setenv("INARI_OUTBOX_POLL_INTERVAL", "5s")
	t.Setenv("INARI_PLATFORM_ADMIN_GROUP", "root-admins")
	t.Setenv("INARI_PLATFORM_GROUP_SYNC_INTERVAL", "10s")
	t.Setenv("INARI_ORG_GROUP_SYNC_INTERVAL", "15s")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.HTTPAddr != ":9090" {
		t.Errorf("HTTPAddr = %q, want :9090", c.HTTPAddr)
	}
	if c.OutboxPollInterval.Seconds() != 5 {
		t.Errorf("OutboxPollInterval = %v, want 5s", c.OutboxPollInterval)
	}
	if c.PlatformAdminGroup != "root-admins" {
		t.Errorf("PlatformAdminGroup = %q, want root-admins", c.PlatformAdminGroup)
	}
	if c.PlatformGroupSyncInterval.Seconds() != 10 {
		t.Errorf("PlatformGroupSyncInterval = %v, want 10s", c.PlatformGroupSyncInterval)
	}
	if c.OrgGroupSyncInterval.Seconds() != 15 {
		t.Errorf("OrgGroupSyncInterval = %v, want 15s", c.OrgGroupSyncInterval)
	}
}

func TestAgentCompatDefaults(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.AgentSupportedRange != "" {
		t.Errorf("AgentSupportedRange = %q, want empty", c.AgentSupportedRange)
	}
	if c.AgentRecommendedVersion != "" {
		t.Errorf("AgentRecommendedVersion = %q, want empty", c.AgentRecommendedVersion)
	}
	if c.AgentFloatLatest {
		t.Error("AgentFloatLatest = true, want false")
	}
}

func TestAgentCompatEnvOverride(t *testing.T) {
	t.Setenv("INARI_AGENT_SUPPORTED_RANGE", ">=0.5.0 <0.6.0")
	t.Setenv("INARI_AGENT_RECOMMENDED_VERSION", "0.5.1")
	t.Setenv("INARI_AGENT_FLOAT_LATEST", "true")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.AgentSupportedRange != ">=0.5.0 <0.6.0" {
		t.Errorf("AgentSupportedRange = %q, want >=0.5.0 <0.6.0", c.AgentSupportedRange)
	}
	if c.AgentRecommendedVersion != "0.5.1" {
		t.Errorf("AgentRecommendedVersion = %q, want 0.5.1", c.AgentRecommendedVersion)
	}
	if !c.AgentFloatLatest {
		t.Error("AgentFloatLatest = false, want true")
	}
}

func TestAgentCompatInvalidRangeFails(t *testing.T) {
	t.Setenv("INARI_AGENT_SUPPORTED_RANGE", "not-a-range")
	if _, err := Load(); err == nil {
		t.Fatal("Load: expected error for invalid INARI_AGENT_SUPPORTED_RANGE")
	}
}

func TestGitStateRepoOrgEnvOverride(t *testing.T) {
	t.Setenv("INARI_GIT_STATE_REPO_ORG", "7k-group")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.GitStateRepoOrg != "7k-group" {
		t.Errorf("GitStateRepoOrg = %q, want 7k-group", c.GitStateRepoOrg)
	}
}

func TestScaffoldEnvOverride(t *testing.T) {
	t.Setenv("INARI_SCAFFOLD_RECONCILE_INTERVAL", "10s")
	t.Setenv("INARI_SCAFFOLD_STEP_MAX_ATTEMPTS", "3")
	t.Setenv("INARI_SCAFFOLD_GIT_ORG", "inari-apps")
	t.Setenv("INARI_SCAFFOLD_TEMPLATE_DIR", "/srv/templates")
	t.Setenv("INARI_SCAFFOLD_RUN_TTL", "24h")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ScaffoldReconcileInterval.Seconds() != 10 {
		t.Errorf("ScaffoldReconcileInterval = %v, want 10s", c.ScaffoldReconcileInterval)
	}
	if c.ScaffoldStepMaxAttempts != 3 {
		t.Errorf("ScaffoldStepMaxAttempts = %d, want 3", c.ScaffoldStepMaxAttempts)
	}
	if c.ScaffoldGitOrg != "inari-apps" {
		t.Errorf("ScaffoldGitOrg = %q, want inari-apps", c.ScaffoldGitOrg)
	}
	if c.ScaffoldTemplateDir != "/srv/templates" {
		t.Errorf("ScaffoldTemplateDir = %q, want /srv/templates", c.ScaffoldTemplateDir)
	}
	if c.ScaffoldRunTTL.Hours() != 24 {
		t.Errorf("ScaffoldRunTTL = %v, want 24h", c.ScaffoldRunTTL)
	}
}

func TestIdentityScopesDefault(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.IdentityScopes) == 0 || c.IdentityScopes[0].Audience != "inari-server" {
		t.Errorf("IdentityScopes = %v, want built-in default", c.IdentityScopes)
	}
	// The kubectl-access audience must be in the built-in catalog (plan §5.4).
	var k8s bool
	for _, s := range c.IdentityScopes {
		if s.Audience == "kubernetes" {
			k8s = true
		}
	}
	if !k8s {
		t.Errorf("IdentityScopes = %v, want a kubernetes audience entry", c.IdentityScopes)
	}
}

func TestIdentityScopesEnvOverride(t *testing.T) {
	t.Setenv("INARI_IDENTITY_SCOPES", `[{"audience":"svc-a","scopes":["x","y"]}]`)
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.IdentityScopes) != 1 || c.IdentityScopes[0].Audience != "svc-a" || len(c.IdentityScopes[0].Scopes) != 2 {
		t.Errorf("IdentityScopes = %v", c.IdentityScopes)
	}
}

func TestIdentityScopesInvalidFallsBack(t *testing.T) {
	t.Setenv("INARI_IDENTITY_SCOPES", `not-json`)
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.IdentityScopes) == 0 || c.IdentityScopes[0].Audience != "inari-server" {
		t.Errorf("IdentityScopes = %v, want fallback default", c.IdentityScopes)
	}
}

func TestCacheEnvDefaults(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.CacheBackend != "memory" {
		t.Errorf("CacheBackend = %q, want memory", c.CacheBackend)
	}
	if c.RedisURL != "redis://localhost:6379/0" {
		t.Errorf("RedisURL = %q, want redis://localhost:6379/0", c.RedisURL)
	}
	if c.CachePEPTTL.Seconds() != 2 {
		t.Errorf("CachePEPTTL = %v, want 2s", c.CachePEPTTL)
	}
	if c.CacheTenantTTL.Seconds() != 10 {
		t.Errorf("CacheTenantTTL = %v, want 10s", c.CacheTenantTTL)
	}
	if c.CacheMemoryMaxEntries != 10000 {
		t.Errorf("CacheMemoryMaxEntries = %d, want 10000", c.CacheMemoryMaxEntries)
	}
}

func TestCacheEnvOverride(t *testing.T) {
	t.Setenv("INARI_CACHE_BACKEND", "redis")
	t.Setenv("INARI_REDIS_URL", "redis://cache:6379/1")
	t.Setenv("INARI_CACHE_PEP_TTL", "5s")
	t.Setenv("INARI_CACHE_TENANT_TTL", "30s")
	t.Setenv("INARI_CACHE_MEMORY_MAX_ENTRIES", "500")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.CacheBackend != "redis" {
		t.Errorf("CacheBackend = %q, want redis", c.CacheBackend)
	}
	if c.RedisURL != "redis://cache:6379/1" {
		t.Errorf("RedisURL = %q", c.RedisURL)
	}
	if c.CachePEPTTL.Seconds() != 5 {
		t.Errorf("CachePEPTTL = %v, want 5s", c.CachePEPTTL)
	}
	if c.CacheTenantTTL.Seconds() != 30 {
		t.Errorf("CacheTenantTTL = %v, want 30s", c.CacheTenantTTL)
	}
	if c.CacheMemoryMaxEntries != 500 {
		t.Errorf("CacheMemoryMaxEntries = %d, want 500", c.CacheMemoryMaxEntries)
	}
}

func TestCacheBackendInvalid(t *testing.T) {
	t.Setenv("INARI_CACHE_BACKEND", "memcached")
	if _, err := Load(); err == nil {
		t.Fatal("Load: want error for unknown cache backend")
	}
}

func TestCacheTTLNonPositive(t *testing.T) {
	for _, tc := range []struct{ key, val string }{
		{"INARI_CACHE_PEP_TTL", "0"},
		{"INARI_CACHE_PEP_TTL", "-5s"},
		{"INARI_CACHE_TENANT_TTL", "0"},
		{"INARI_CACHE_TENANT_TTL", "-1s"},
	} {
		t.Run(tc.key+"="+tc.val, func(t *testing.T) {
			t.Setenv(tc.key, tc.val)
			if _, err := Load(); err == nil {
				t.Fatalf("Load: want error for %s=%s (ttl <= 0 never expires in both backends)", tc.key, tc.val)
			}
		})
	}
}

func TestNATSURLRequired(t *testing.T) {
	t.Setenv("INARI_NATS_URL", "")
	if _, err := Load(); err == nil {
		t.Fatal("Load with empty INARI_NATS_URL = nil error, want required-validation error")
	}
}

func TestNATSStreamReplicasEnv(t *testing.T) {
	t.Setenv("INARI_NATS_STREAM_REPLICAS", "3")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.NATSStreamReplicas != 3 {
		t.Errorf("NATSStreamReplicas = %d, want 3", c.NATSStreamReplicas)
	}
}

func TestNATSStreamReplicasInvalid(t *testing.T) {
	t.Setenv("INARI_NATS_STREAM_REPLICAS", "0")
	if _, err := Load(); err == nil {
		t.Fatal("Load with INARI_NATS_STREAM_REPLICAS=0 = nil error, want validation error")
	}
}

func TestRoleValid(t *testing.T) {
	t.Setenv("INARI_DATABASE_URL", "postgres://x")
	if _, err := Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
}

func TestGitHubResolverEnv(t *testing.T) {
	t.Setenv("INARI_GITHUB_API_BASE", "https://ghe.example.com/api/v3")
	t.Setenv("INARI_GITHUB_APP_SLUG", "inari-platform")
	t.Setenv("INARI_GITHUB_INSTALL_CACHE_TTL", "10m")
	t.Setenv("INARI_GITHUB_ALLOWED_API_BASES", "ghe.corp.example,ghe2.corp.example")
	t.Setenv("INARI_TENANT_GIT_KEY_MOUNT_ROOT", "/keys")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.GitHubAPIBase != "https://ghe.example.com/api/v3" {
		t.Errorf("GitHubAPIBase = %q", c.GitHubAPIBase)
	}
	if c.GitHubAppSlug != "inari-platform" {
		t.Errorf("GitHubAppSlug = %q", c.GitHubAppSlug)
	}
	if c.GitHubInstallCacheTTL.Minutes() != 10 {
		t.Errorf("GitHubInstallCacheTTL = %v", c.GitHubInstallCacheTTL)
	}
	if len(c.GitHubAllowedAPIBases) != 2 || c.GitHubAllowedAPIBases[0] != "ghe.corp.example" {
		t.Errorf("GitHubAllowedAPIBases = %v", c.GitHubAllowedAPIBases)
	}
	if c.TenantGitKeyMountRoot != "/keys" {
		t.Errorf("TenantGitKeyMountRoot = %q", c.TenantGitKeyMountRoot)
	}
}

func TestGitHubResolverEnvDefaults(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.GitHubAPIBase != "" {
		t.Errorf("GitHubAPIBase default = %q, want empty (github.com)", c.GitHubAPIBase)
	}
	if c.GitHubInstallCacheTTL.Minutes() != 5 {
		t.Errorf("GitHubInstallCacheTTL default = %v, want 5m", c.GitHubInstallCacheTTL)
	}
	if c.TenantGitKeyMountRoot != "/var/run/inari/tenant-git-keys" {
		t.Errorf("TenantGitKeyMountRoot default = %q", c.TenantGitKeyMountRoot)
	}
}

func TestOptionalBoolEnvThreeState(t *testing.T) {
	const key = "INARI_KUBECTL_ACCESS_ENABLED"

	// Unset: nil — runtime flag wins (kill-switch v2 precedence).
	if v := optionalBoolEnv(key); v != nil {
		t.Errorf("unset: got %v, want nil", *v)
	}

	t.Setenv(key, "")
	if v := optionalBoolEnv(key); v != nil {
		t.Errorf("empty: got %v, want nil", *v)
	}

	t.Setenv(key, "false")
	if v := optionalBoolEnv(key); v == nil || *v {
		t.Errorf("false: got %v, want pointer to false", v)
	}

	t.Setenv(key, "true")
	if v := optionalBoolEnv(key); v == nil || !*v {
		t.Errorf("true: got %v, want pointer to true", v)
	}

	// Unparseable: treated as explicitly set to the safe default (true) — a
	// typoed kill-switch never silently hands control to runtime state.
	t.Setenv(key, "banana")
	if v := optionalBoolEnv(key); v == nil || !*v {
		t.Errorf("invalid: got %v, want pointer to true", v)
	}
}

func TestKubectlAccessEnabledDefaultsUnset(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.KubectlAccessEnabled != nil {
		t.Errorf("server KubectlAccessEnabled = %v, want nil (unset)", *c.KubectlAccessEnabled)
	}
	kc, err := LoadKubeproxy()
	if err != nil {
		t.Fatalf("LoadKubeproxy: %v", err)
	}
	if kc.KubectlAccessEnabled != nil {
		t.Errorf("kubeproxy KubectlAccessEnabled = %v, want nil (unset)", *kc.KubectlAccessEnabled)
	}
	if c.CacheFlagsTTL.Seconds() != 10 {
		t.Errorf("CacheFlagsTTL = %v, want 10s", c.CacheFlagsTTL)
	}
}
