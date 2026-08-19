package policyservice

import (
	"context"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestOPAEvalDenyAsPlainStrings(t *testing.T) {
	ev := NewOPAEvaluator()
	p := &types.Policy{Source: `package inari.policy

deny contains "no-public-images" if {
	input.spec.image != "registry.example.com/app"
}
`}
	denies, _, err := ev.Eval(context.Background(), p, map[string]any{
		"spec": map[string]any{"image": "evil.io/app"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(denies) != 1 || denies[0].Reason != "no-public-images" {
		t.Fatalf("string deny entries must surface as violations, got %+v", denies)
	}
}

func TestOPACompileRejectsWrongPackage(t *testing.T) {
	ev := NewOPAEvaluator()
	src := `package typo.policy

deny contains {"rule": "r", "reason": "x", "remediation": "y"} if { true }
`
	err := ev.Compile(src)
	if err == nil || !strings.Contains(err.Error(), "inari.policy") {
		t.Fatalf("wrong package must be rejected at compile time, got %v", err)
	}
}
