package approvals

import (
	"errors"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.DefaultPolicy != types.ApprovalPolicyAuto {
		t.Errorf("default policy = %q, want auto", cfg.DefaultPolicy)
	}
	if cfg.ApprovalTTL != DefaultTTL.String() {
		t.Errorf("default TTL = %q, want %q", cfg.ApprovalTTL, DefaultTTL.String())
	}
	if err := validateConfig(&cfg); err != nil {
		t.Errorf("default config must validate: %v", err)
	}
}

func TestValidateConfig(t *testing.T) {
	valid := func() *types.ApprovalConfig {
		return &types.ApprovalConfig{
			DefaultPolicy: types.ApprovalPolicyPeer,
			ApprovalTTL:   "24h",
			Thresholds: []types.ApprovalThreshold{
				{Kind: "cost", Gt: 1000, Policy: types.ApprovalPolicyPlatformAdmin},
			},
			ApproverGroups: []types.ApproverGroup{
				{Name: "sre", Subjects: []string{"user:a"}},
			},
			AutoApprove: []types.AutoApproveRule{
				{Kind: "catalog_item", ItemIDs: []string{"item-1"}},
			},
		}
	}
	if err := validateConfig(valid()); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*types.ApprovalConfig)
	}{
		{"empty default policy", func(c *types.ApprovalConfig) { c.DefaultPolicy = "" }},
		{"unknown default policy", func(c *types.ApprovalConfig) { c.DefaultPolicy = "magic" }},
		{"empty ttl", func(c *types.ApprovalConfig) { c.ApprovalTTL = "" }},
		{"malformed ttl", func(c *types.ApprovalConfig) { c.ApprovalTTL = "soon" }},
		{"non-positive ttl", func(c *types.ApprovalConfig) { c.ApprovalTTL = "0s" }},
		{"negative ttl", func(c *types.ApprovalConfig) { c.ApprovalTTL = "-1h" }},
		{"threshold empty kind", func(c *types.ApprovalConfig) { c.Thresholds[0].Kind = "" }},
		{"threshold negative gt", func(c *types.ApprovalConfig) { c.Thresholds[0].Gt = -1 }},
		{"threshold unknown policy", func(c *types.ApprovalConfig) { c.Thresholds[0].Policy = "nobody" }},
		{"group empty name", func(c *types.ApprovalConfig) { c.ApproverGroups[0].Name = "" }},
		{"group no subjects", func(c *types.ApprovalConfig) { c.ApproverGroups[0].Subjects = nil }},
		{"auto-approve empty kind", func(c *types.ApprovalConfig) { c.AutoApprove[0].Kind = "" }},
		{"auto-approve no items", func(c *types.ApprovalConfig) { c.AutoApprove[0].ItemIDs = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid()
			tc.mutate(cfg)
			err := validateConfig(cfg)
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("err = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestConfigTTLDuration(t *testing.T) {
	cfg := DefaultConfig()
	d, err := cfg.TTLDuration()
	if err != nil {
		t.Fatal(err)
	}
	if d != DefaultTTL {
		t.Errorf("TTL = %v, want %v", d, DefaultTTL)
	}
	cfg.ApprovalTTL = "30m"
	d, err = cfg.TTLDuration()
	if err != nil || d != 30*time.Minute {
		t.Errorf("TTL = %v, %v; want 30m", d, err)
	}
	if _, err := (&types.ApprovalConfig{ApprovalTTL: "soon"}).TTLDuration(); err == nil {
		t.Error("malformed TTL must error")
	}
}
