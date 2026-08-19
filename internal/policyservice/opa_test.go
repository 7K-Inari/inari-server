package policyservice

import (
	"context"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

const denyRegistryRego = `package inari.policy

deny contains {"rule": "disallowed-registry", "reason": "image not from approved registry", "remediation": "use registry.example.com"} if {
	input.spec.image != "registry.example.com/app"
}
`

func TestOPAEvalDeny(t *testing.T) {
	ev := NewOPAEvaluator()
	p := &types.Policy{Source: denyRegistryRego}
	denies, warns, err := ev.Eval(context.Background(), p, map[string]any{
		"spec": map[string]any{"image": "evil.io/app"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(denies) != 1 {
		t.Fatalf("denies = %v, want 1", denies)
	}
	d := denies[0]
	if d.Rule != "disallowed-registry" || d.Reason == "" || d.Remediation == "" {
		t.Errorf("unexpected violation: %+v", d)
	}
	if len(warns) != 0 {
		t.Errorf("warns = %v, want none", warns)
	}
}

func TestOPAEvalAllow(t *testing.T) {
	ev := NewOPAEvaluator()
	p := &types.Policy{Source: denyRegistryRego}
	denies, _, err := ev.Eval(context.Background(), p, map[string]any{
		"spec": map[string]any{"image": "registry.example.com/app"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(denies) != 0 {
		t.Fatalf("denies = %v, want none", denies)
	}
}

func TestOPAEvalWarn(t *testing.T) {
	ev := NewOPAEvaluator()
	p := &types.Policy{Source: `package inari.policy

warn contains {"rule": "no-liveness-probe", "reason": "missing liveness probe", "remediation": "add one"} if {
	true
}
`}
	_, warns, err := ev.Eval(context.Background(), p, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 1 || warns[0].Rule != "no-liveness-probe" {
		t.Fatalf("warns = %+v", warns)
	}
}

func TestOPACompileRejectsBrokenRego(t *testing.T) {
	ev := NewOPAEvaluator()
	if err := ev.Compile("package inari.policy\n\ndeny if {"); err == nil {
		t.Fatal("expected compile error for broken rego")
	}
	if err := ev.Compile(denyRegistryRego); err != nil {
		t.Fatalf("valid rego rejected: %v", err)
	}
}
