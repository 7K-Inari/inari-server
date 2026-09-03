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
}

func TestLoadEnvOverride(t *testing.T) {
	t.Setenv("INARI_HTTP_ADDR", ":9090")
	t.Setenv("INARI_OUTBOX_POLL_INTERVAL", "5s")
	t.Setenv("INARI_PLATFORM_ADMIN_GROUP", "root-admins")
	t.Setenv("INARI_PLATFORM_GROUP_SYNC_INTERVAL", "10s")
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
}

func TestRoleValid(t *testing.T) {
	t.Setenv("INARI_DATABASE_URL", "postgres://x")
	if _, err := Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
}
