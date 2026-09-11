package config

import "testing"

func TestLoadDefaults(t *testing.T) {
	t.Setenv("INARI_HTTP_ADDR", "")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
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

func TestRoleValid(t *testing.T) {
	t.Setenv("INARI_DATABASE_URL", "postgres://x")
	if _, err := Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
}
