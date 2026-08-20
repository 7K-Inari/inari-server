package fleetmanager

import (
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestCanRolloutTransition(t *testing.T) {
	cases := []struct {
		from, to string
		want     bool
	}{
		{types.RolloutStatePending, types.RolloutStateRunning, true},
		{types.RolloutStatePending, types.RolloutStateCompleted, false},
		{types.RolloutStateRunning, types.RolloutStateWaitingGate, true},
		{types.RolloutStateRunning, types.RolloutStatePaused, true},
		{types.RolloutStateRunning, types.RolloutStateRolledBack, true},
		{types.RolloutStateWaitingGate, types.RolloutStateRunning, true},
		{types.RolloutStateWaitingGate, types.RolloutStateCompleted, false},
		{types.RolloutStatePaused, types.RolloutStateRunning, true},
		{types.RolloutStatePaused, types.RolloutStateCompleted, false},
		{types.RolloutStateFailed, types.RolloutStateRolledBack, true},
		{types.RolloutStateFailed, types.RolloutStateRunning, true},
		{types.RolloutStateCompleted, types.RolloutStateRolledBack, true},
		{types.RolloutStateCompleted, types.RolloutStateRunning, false},
		{types.RolloutStateRolledBack, types.RolloutStateRunning, false},
	}
	for _, c := range cases {
		if got := CanRolloutTransition(c.from, c.to); got != c.want {
			t.Errorf("CanRolloutTransition(%s, %s) = %v, want %v", c.from, c.to, got, c.want)
		}
	}
}

func TestParseMaxConcurrency(t *testing.T) {
	cases := []struct {
		spec  string
		total int
		want  int
		err   bool
	}{
		{"3", 10, 3, false},
		{"20", 10, 10, false}, // clamped to total
		{"25%", 10, 3, false}, // ceil(2.5)
		{"1%", 10, 1, false},  // min 1
		{"100%", 4, 4, false},
		{"50%", 1, 1, false},
		{"0%", 10, 0, true},
		{"150%", 10, 0, true},
		{"0", 10, 0, true},
		{"-2", 10, 0, true},
		{"abc", 10, 0, true},
		{"", 10, 0, true},
		{"5", 0, 0, false}, // empty stage: zero
	}
	for _, c := range cases {
		got, err := ParseMaxConcurrency(c.spec, c.total)
		if (err != nil) != c.err {
			t.Errorf("ParseMaxConcurrency(%q, %d) err = %v, want err=%v", c.spec, c.total, err, c.err)
			continue
		}
		if !c.err && got != c.want {
			t.Errorf("ParseMaxConcurrency(%q, %d) = %d, want %d", c.spec, c.total, got, c.want)
		}
	}
}

func TestMatchesSelector(t *testing.T) {
	labels := map[string]string{"env": "prod", "region": "eu"}
	if !MatchesSelector(labels, map[string]string{"env": "prod"}) {
		t.Error("subset should match")
	}
	if !MatchesSelector(labels, map[string]string{"env": "prod", "region": "eu"}) {
		t.Error("exact should match")
	}
	if MatchesSelector(labels, map[string]string{"env": "dev"}) {
		t.Error("value mismatch should not match")
	}
	if MatchesSelector(labels, map[string]string{"zone": "a"}) {
		t.Error("missing key should not match")
	}
	if !MatchesSelector(labels, map[string]string{}) {
		t.Error("empty selector matches everything")
	}
}

func TestSupportedAgentVersion(t *testing.T) {
	cases := []struct {
		current, reported string
		want              bool
	}{
		{"v1.5.0", "v1.5.2", true},  // N
		{"v1.5.0", "v1.4.9", true},  // N-1
		{"v1.5.0", "v1.3.0", false}, // N-2 unsupported
		{"v1.5.0", "v1.6.0", false}, // newer than control plane
		{"v1.5.0", "v2.5.0", false}, // major mismatch
		{"1.5.0", "1.4.0", true},    // no v prefix
		{"v1.5.0", "garbage", false},
		{"garbage", "v1.5.0", false},
	}
	for _, c := range cases {
		if got := SupportedAgentVersion(c.current, c.reported); got != c.want {
			t.Errorf("SupportedAgentVersion(%q, %q) = %v, want %v", c.current, c.reported, got, c.want)
		}
	}
}

func TestValidateStages(t *testing.T) {
	if err := validateStages(nil); err == nil {
		t.Error("empty stages should fail")
	}
	ok := []types.RolloutStage{{Name: "canary", ClusterSetIDs: []string{"clusterset:1"}, MaxConcurrency: "1"}}
	if err := validateStages(ok); err != nil {
		t.Errorf("valid stages: %v", err)
	}
	noSets := []types.RolloutStage{{Name: "x", MaxConcurrency: "1"}}
	if err := validateStages(noSets); err == nil {
		t.Error("stage without cluster sets should fail")
	}
	badGate := []types.RolloutStage{{
		Name: "x", ClusterSetIDs: []string{"clusterset:1"}, MaxConcurrency: "1",
		AfterGate: &types.RolloutStageGate{Type: "bogus"},
	}}
	if err := validateStages(badGate); err == nil {
		t.Error("bad gate type should fail")
	}
	badWait := []types.RolloutStage{{
		Name: "x", ClusterSetIDs: []string{"clusterset:1"}, MaxConcurrency: "1",
		BeforeGate: &types.RolloutStageGate{Type: "wait"},
	}}
	if err := validateStages(badWait); err == nil {
		t.Error("wait gate without waitSeconds should fail")
	}
}
