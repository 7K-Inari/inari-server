package fleetmanager

import "testing"

func TestSupportedAgentVersionInRange(t *testing.T) {
	cases := []struct {
		rangeExpr, reported string
		want                bool
		wantErr             bool
	}{
		{">=0.5.0 <0.6.0", "0.5.1", true, false},
		{">=0.5.0 <0.6.0", "v0.5.0", true, false}, // v prefix tolerated
		{">=0.5.0 <0.6.0", "0.6.0", false, false},
		{">=0.5.0 <0.6.0", "0.4.9", false, false},
		{">=0.5.0 <0.6.0", "1.5.0", false, false},
		{">=0.5.0 <0.6.0", "garbage", false, true},
		{"nonsense", "0.5.1", false, true},
		{"", "0.5.1", false, true},
	}
	for _, c := range cases {
		got, err := SupportedAgentVersionInRange(c.rangeExpr, c.reported)
		if (err != nil) != c.wantErr {
			t.Errorf("SupportedAgentVersionInRange(%q, %q) err = %v, wantErr %v", c.rangeExpr, c.reported, err, c.wantErr)
		}
		if err == nil && got != c.want {
			t.Errorf("SupportedAgentVersionInRange(%q, %q) = %v, want %v", c.rangeExpr, c.reported, got, c.want)
		}
	}
}

func TestAgentSupported(t *testing.T) {
	cases := []struct {
		name                              string
		supportedRange, current, reported string
		want                              bool
	}{
		{"range hit", ">=0.5.0 <0.6.0", "0.5.2", "0.5.1", true},
		{"range miss", ">=0.5.0 <0.6.0", "0.5.2", "0.6.0", false},
		// Range takes precedence over N/N-1: a version N-1 by the legacy
		// policy but outside the declared range is unsupported.
		{"range beats N-1", ">=0.5.0 <0.6.0", "0.6.0", "0.5.9", true},
		{"range beats N/N-1 mismatch", ">=0.6.0 <0.7.0", "0.5.0", "0.5.0", false},
		// Fallback: no range -> legacy N/N-1 on current.
		{"fallback N", "", "v1.5.0", "v1.5.2", true},
		{"fallback N-1", "", "v1.5.0", "v1.4.9", true},
		{"fallback N-2", "", "v1.5.0", "v1.3.0", false},
		// Neither configured -> check disabled (admit).
		{"unset admits", "", "", "anything", true},
		// Invalid range -> fail closed (operator misconfiguration).
		{"invalid range fails closed", "nonsense", "0.5.0", "0.5.0", false},
	}
	for _, c := range cases {
		if got := AgentSupported(c.supportedRange, c.current, c.reported); got != c.want {
			t.Errorf("%s: AgentSupported(%q, %q, %q) = %v, want %v",
				c.name, c.supportedRange, c.current, c.reported, got, c.want)
		}
	}
}

func TestUpgradeAvailable(t *testing.T) {
	cases := []struct {
		recommended, reported string
		want                  bool
	}{
		{"0.5.1", "0.5.0", true},
		{"0.5.1", "v0.5.0", true},
		{"0.5.1", "0.5.1", false},
		{"0.5.1", "0.5.2", false}, // ahead of recommendation
		{"0.5.1", "0.6.0", false},
		{"", "0.5.0", false}, // no recommendation configured
		{"0.5.1", "", false}, // agent never reported
		{"0.5.1", "garbage", false},
		{"garbage", "0.5.0", false},
	}
	for _, c := range cases {
		if got := UpgradeAvailable(c.recommended, c.reported); got != c.want {
			t.Errorf("UpgradeAvailable(%q, %q) = %v, want %v", c.recommended, c.reported, got, c.want)
		}
	}
}
