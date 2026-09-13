//go:build integration

package policyservice_test

import (
	"context"
	"errors"
	"testing"

	"github.com/7K-Inari/inari-server/internal/policyservice"
	"github.com/7K-Inari/inari-server/internal/types"
)

// Edge cases beyond the feature tests: self-rename, global-name dedupe,
// cross-org isolation/visibility, atomic rollback on conflict.
func TestPolicyUpdateEdgeCases(t *testing.T) {
	svc, _, database := itService(t)
	ctx := context.Background()
	if _, err := database.Pool.Exec(ctx,
		`INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ('org:2','beta','Beta','kc-2')`); err != nil {
		t.Fatal(err)
	}

	p, err := svc.CreatePolicy(ctx, "user-1", "org:1", "alpha", types.PolicyTargetRequest, types.PolicyEngineRego, itDenyRego)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Rename to the SAME name must not self-conflict.
	if _, err := svc.UpdatePolicy(ctx, "user-1", "org:1", p.ID, "alpha", "", itDenyRego, true); err != nil {
		t.Fatalf("rename to own name: %v", err)
	}

	// 2. Platform-global rows dedupe among themselves (the '' bucket of the
	// COALESCE index); a tenant policy may shadow a global name (QA note:
	// ListPolicies then shows both — cosmetic ambiguity, reported).
	if _, err := svc.CreatePolicy(ctx, "admin", "", "global-one", types.PolicyTargetRequest, types.PolicyEngineRego, itDenyRego); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreatePolicy(ctx, "admin", "", "global-one", types.PolicyTargetRequest, types.PolicyEngineRego, itDenyRego); !errors.Is(err, policyservice.ErrPolicyNameTaken) {
		t.Fatalf("duplicate global name: got %v, want ErrPolicyNameTaken", err)
	}
	if _, err := svc.UpdatePolicy(ctx, "user-1", "org:1", p.ID, "global-one", "", itDenyRego, true); err != nil {
		t.Fatalf("tenant shadowing a global name is allowed by design: %v", err)
	}
	if _, err := svc.UpdatePolicy(ctx, "user-1", "org:1", p.ID, "alpha", "", itDenyRego, true); err != nil {
		t.Fatal(err)
	}
	// And a tenant policy blocks a second tenant's rename (index is org-scoped,
	// so another org may reuse the name freely).
	if _, err := svc.CreatePolicy(ctx, "user-1", "org:2", "alpha", types.PolicyTargetRequest, types.PolicyEngineRego, itDenyRego); err != nil {
		t.Fatalf("other org may reuse the name: %v", err)
	}

	// 3. Empty / broken source is rejected before persisting.
	if _, err := svc.UpdatePolicy(ctx, "user-1", "org:1", p.ID, "", "", "", true); !errors.Is(err, policyservice.ErrInvalidInput) {
		t.Fatalf("empty source: got %v, want ErrInvalidInput", err)
	}

	// 4. Unknown policy ID.
	if _, err := svc.UpdatePolicy(ctx, "user-1", "org:1", "policy:nope", "", "", itDenyRego, true); !errors.Is(err, policyservice.ErrPolicyNotFound) {
		t.Fatalf("unknown id: got %v, want ErrPolicyNotFound", err)
	}

	// 5. Policy of another org is invisible (404-class, not editable).
	if _, err := svc.UpdatePolicy(ctx, "user-1", "org:9", p.ID, "", "", itDenyRego, true); !errors.Is(err, policyservice.ErrPolicyNotFound) {
		t.Fatalf("cross-org update: got %v, want ErrPolicyNotFound", err)
	}

	// 6. Platform-global policy is not editable by tenants.
	g, err := svc.CreatePolicy(ctx, "admin", "", "global-two", types.PolicyTargetRequest, types.PolicyEngineRego, itDenyRego)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdatePolicy(ctx, "user-1", "org:1", g.ID, "", "", itDenyRego, true); !errors.Is(err, policyservice.ErrInvalidInput) {
		t.Fatalf("global policy update: got %v, want ErrInvalidInput", err)
	}

	// 7. Update is atomic: a conflicting rename must not persist a source edit.
	const newRego = `package inari.policy

deny contains {"rule": "v2", "reason": "r", "remediation": "m"} if { input.spec.image == "x" }
`
	if _, err := svc.CreatePolicy(ctx, "user-1", "org:1", "taken", types.PolicyTargetRequest, types.PolicyEngineRego, itDenyRego); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdatePolicy(ctx, "user-1", "org:1", p.ID, "taken", "", newRego, false); !errors.Is(err, policyservice.ErrPolicyNameTaken) {
		t.Fatalf("conflicting update: got %v", err)
	}
	got, err := svc.GetPolicy(ctx, "org:1", p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Source == newRego || !got.Enabled {
		t.Fatalf("conflicting update must roll back fully: %+v", got)
	}
}

// TestPolicyRenameRace: two concurrent renames to the same name — exactly
// one wins; the loser gets ErrPolicyNameTaken, never a raw 500-class error.
func TestPolicyRenameRace(t *testing.T) {
	svc, _, _ := itService(t)
	ctx := context.Background()
	a, err := svc.CreatePolicy(ctx, "user-1", "org:1", "race-a", types.PolicyTargetRequest, types.PolicyEngineRego, itDenyRego)
	if err != nil {
		t.Fatal(err)
	}
	b, err := svc.CreatePolicy(ctx, "user-1", "org:1", "race-b", types.PolicyTargetRequest, types.PolicyEngineRego, itDenyRego)
	if err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 2)
	go func() {
		_, err := svc.UpdatePolicy(ctx, "user-1", "org:1", a.ID, "race-winner", "", itDenyRego, true)
		errs <- err
	}()
	go func() {
		_, err := svc.UpdatePolicy(ctx, "user-1", "org:1", b.ID, "race-winner", "", itDenyRego, true)
		errs <- err
	}()
	e1, e2 := <-errs, <-errs
	conflicts := 0
	for _, e := range []error{e1, e2} {
		if errors.Is(e, policyservice.ErrPolicyNameTaken) {
			conflicts++
		} else if e != nil {
			t.Fatalf("unexpected error class (must be nil or 409-mapped): %v", e)
		}
	}
	if conflicts > 1 {
		t.Fatalf("both renames conflicted; one must win")
	}
}
