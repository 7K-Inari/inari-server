package config

import (
	"testing"
	"time"
)

func TestPlanLimitsAndTenantProvisioningConfig(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PlanLimitsProvider != "unlimited" || cfg.MeteringEmitter != "noop" || len(cfg.TenantProvisioningIdentities) != 0 {
		t.Fatalf("unsafe defaults: %+v", cfg)
	}
	if cfg.PlanLimitsCacheTTL != 30*time.Second || cfg.PlanLimitsUpgradeURL != "" {
		t.Fatalf("plan-limit defaults: ttl=%s upgrade=%q", cfg.PlanLimitsCacheTTL, cfg.PlanLimitsUpgradeURL)
	}
	t.Setenv("INARI_PLAN_LIMITS_PROVIDER", "keycloak")
	t.Setenv("INARI_METERING_EMITTER", "outbox")
	t.Setenv("INARI_PLAN_LIMITS_CACHE_TTL", "0s")
	t.Setenv("INARI_PLAN_LIMITS_UPGRADE_URL", "https://7kgroup.org")
	t.Setenv("INARI_TENANT_PROVISIONING_IDENTITIES", "client-a:subject-a, client-b:subject-b")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PlanLimitsProvider != "keycloak" || cfg.MeteringEmitter != "outbox" {
		t.Fatalf("overrides not loaded: %+v", cfg)
	}
	if cfg.PlanLimitsCacheTTL != 0 || cfg.PlanLimitsUpgradeURL != "https://7kgroup.org" {
		t.Fatalf("plan-limit overrides: ttl=%s upgrade=%q", cfg.PlanLimitsCacheTTL, cfg.PlanLimitsUpgradeURL)
	}
	if cfg.TenantProvisioningIdentities["client-a"] != "subject-a" || cfg.TenantProvisioningIdentities["client-b"] != "subject-b" {
		t.Fatalf("identities = %#v", cfg.TenantProvisioningIdentities)
	}
}

func TestInvalidPlanLimitCacheAndUpgradeConfig(t *testing.T) {
	t.Setenv("INARI_PLAN_LIMITS_CACHE_TTL", "-1s")
	if _, err := Load(); err == nil {
		t.Fatal("accepted negative plan-limit cache TTL")
	}
	t.Setenv("INARI_PLAN_LIMITS_CACHE_TTL", "30s")
	t.Setenv("INARI_PLAN_LIMITS_UPGRADE_URL", "http://7kgroup.org")
	if _, err := Load(); err == nil {
		t.Fatal("accepted non-HTTPS upgrade URL")
	}
}

func TestInvalidPlanLimitsAndTenantProvisioningConfig(t *testing.T) {
	t.Setenv("INARI_PLAN_LIMITS_PROVIDER", "remote")
	if _, err := Load(); err == nil {
		t.Fatal("accepted unknown limits provider")
	}
	t.Setenv("INARI_PLAN_LIMITS_PROVIDER", "unlimited")
	t.Setenv("INARI_TENANT_PROVISIONING_IDENTITIES", "client-without-subject")
	if _, err := Load(); err == nil {
		t.Fatal("accepted malformed service identity")
	}
}
