package policyservice

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"

	"github.com/7K-Inari/inari-server/internal/types"
)

// Evaluator is the policy-engine seam (plan §5.11). v1 ships only Rego via
// OPAEvaluator; other engines plug in behind this interface.
type Evaluator interface {
	// Eval runs one policy against input and returns the deny/warn sets.
	Eval(ctx context.Context, policy *types.Policy, input map[string]any) (denies []types.PolicyViolation, warns []types.PolicyViolation, err error)
	// Compile validates that source parses and compiles.
	Compile(source string) error
}

// OPAEvaluator evaluates Rego policies with an embedded OPA. Per-call
// PrepareForEval is fine for v1 volume; a prepared-query cache keyed by
// policy ID+version is the documented follow-up.
type OPAEvaluator struct{}

func NewOPAEvaluator() *OPAEvaluator { return &OPAEvaluator{} }

func (OPAEvaluator) query(source string) *rego.Rego {
	return rego.New(
		rego.Query("data.inari.policy"),
		rego.Module("policy.rego", source),
		rego.SetRegoVersion(ast.RegoV1),
	)
}

func (e OPAEvaluator) Compile(source string) error {
	_, err := e.query(source).PrepareForEval(context.Background())
	if err != nil {
		return fmt.Errorf("policyservice: rego compile: %w", err)
	}
	return nil
}

func (e OPAEvaluator) Eval(ctx context.Context, policy *types.Policy, input map[string]any) ([]types.PolicyViolation, []types.PolicyViolation, error) {
	pq, err := e.query(policy.Source).PrepareForEval(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("policyservice: rego compile: %w", err)
	}
	rs, err := pq.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, nil, fmt.Errorf("policyservice: rego eval: %w", err)
	}
	var denies, warns []types.PolicyViolation
	for _, result := range rs {
		for _, expr := range result.Expressions {
			doc, ok := expr.Value.(map[string]any)
			if !ok {
				continue
			}
			denies = append(denies, violationsFrom(doc["deny"])...)
			warns = append(warns, violationsFrom(doc["warn"])...)
		}
	}
	return denies, warns, nil
}

// violationsFrom maps a deny/warn result set (entries are objects with
// rule/reason/remediation) into PolicyViolations.
func violationsFrom(v any) []types.PolicyViolation {
	set, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []types.PolicyViolation
	for _, item := range set {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, types.PolicyViolation{
			Rule:        stringOf(m["rule"]),
			Reason:      stringOf(m["reason"]),
			Remediation: stringOf(m["remediation"]),
		})
	}
	return out
}

func stringOf(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
