package config

import "testing"

func TestPlanLimitsAndTenantProvisioningConfig(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PlanLimitsProvider != "unlimited" || cfg.MeteringEmitter != "noop" || len(cfg.TenantProvisioningIdentities) != 0 {
		t.Fatalf("unsafe defaults: %+v", cfg)
	}
	t.Setenv("INARI_PLAN_LIMITS_PROVIDER", "keycloak")
	t.Setenv("INARI_METERING_EMITTER", "outbox")
	t.Setenv("INARI_TENANT_PROVISIONING_IDENTITIES", "client-a:subject-a, client-b:subject-b")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PlanLimitsProvider != "keycloak" || cfg.MeteringEmitter != "outbox" {
		t.Fatalf("overrides not loaded: %+v", cfg)
	}
	if cfg.TenantProvisioningIdentities["client-a"] != "subject-a" || cfg.TenantProvisioningIdentities["client-b"] != "subject-b" {
		t.Fatalf("identities = %#v", cfg.TenantProvisioningIdentities)
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
