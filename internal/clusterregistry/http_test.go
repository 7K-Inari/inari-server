package clusterregistry

import (
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestEnrichAgentCompat(t *testing.T) {
	cases := []struct {
		name                                               string
		supportedRange, current, recommended, agentVersion string
		wantNil                                            bool
		wantSupported, wantUpgrade                         bool
	}{
		{"no policy omits block", "", "", "", "0.5.0", true, false, false},
		{"in range", ">=0.5.0 <0.6.0", "", "0.5.1", "0.5.1", false, true, false},
		{"out of range", ">=0.5.0 <0.6.0", "", "0.5.1", "0.6.0", false, false, false},
		{"behind recommended", ">=0.5.0 <0.6.0", "", "0.5.1", "0.5.0", false, true, true},
		{"legacy N/N-1 fallback", "", "1.5.0", "", "1.4.9", false, true, false},
		{"legacy skew", "", "1.5.0", "", "1.3.0", false, false, false},
		{"recommended only", "", "", "0.5.1", "0.5.0", false, true, true},
		{"agent never reported", ">=0.5.0 <0.6.0", "", "0.5.1", "", false, false, false},
	}
	for _, c := range cases {
		h := NewHandler(nil, nil, nil, nil).
			WithAgentCompat(c.supportedRange, c.current, c.recommended)
		cl := &types.Cluster{AgentVersion: c.agentVersion}
		h.enrichAgentCompat(cl)
		if c.wantNil {
			if cl.AgentCompat != nil {
				t.Errorf("%s: AgentCompat = %+v, want nil", c.name, cl.AgentCompat)
			}
			continue
		}
		if cl.AgentCompat == nil {
			t.Errorf("%s: AgentCompat = nil, want populated", c.name)
			continue
		}
		if cl.AgentCompat.Supported != c.wantSupported {
			t.Errorf("%s: Supported = %v, want %v", c.name, cl.AgentCompat.Supported, c.wantSupported)
		}
		if cl.AgentCompat.UpgradeAvailable != c.wantUpgrade {
			t.Errorf("%s: UpgradeAvailable = %v, want %v", c.name, cl.AgentCompat.UpgradeAvailable, c.wantUpgrade)
		}
		if cl.AgentCompat.RecommendedVersion != c.recommended {
			t.Errorf("%s: RecommendedVersion = %q, want %q", c.name, cl.AgentCompat.RecommendedVersion, c.recommended)
		}
	}
}
