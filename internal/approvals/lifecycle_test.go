package approvals

import (
	"context"
	"errors"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestLifecycleDecisionGuards(t *testing.T) {
	req := &types.ApprovalRequest{
		Action:    types.ApprovalActionTenantZoneDecommission,
		Requester: "user-alice",
	}
	if err := checkLifecycleApprover(req, "user-bob", types.RoleDeveloper); err == nil {
		t.Error("developer must not decide lifecycle approvals")
	}
	if err := checkLifecycleApprover(req, "user-bob", types.RolePlatformEngineer); err != nil {
		t.Errorf("platform engineer decides lifecycle approvals: %v", err)
	}
	if err := checkLifecycleApprover(req, "user-bob", types.RoleOrgAdmin); err != nil {
		t.Errorf("org admin decides lifecycle approvals: %v", err)
	}
	if err := checkLifecycleApprover(req, "user-alice", types.RolePlatformEngineer); err == nil {
		t.Error("requester must not decide their own lifecycle request")
	}
}

type fakePlatformChecker struct{ ok bool }

func (f fakePlatformChecker) Check(context.Context, string, string, string) (bool, error) {
	return f.ok, nil
}

type fakeRoleResolver struct {
	role types.Role
	err  error
}

func (f fakeRoleResolver) RoleOf(context.Context, string, string) (types.Role, error) {
	return f.role, f.err
}

// TestAuthorizeLifecycleApprover pins the platform-admin policy on lifecycle
// decisions (issue #74): a tenant freeze sweeps the org's FGA tuples before
// the approval is decided, so authorization must accept a platform
// org_creator OR a DB-backed org-admin/platform-engineer role.
func TestAuthorizeLifecycleApprover(t *testing.T) {
	req := &types.ApprovalRequest{
		OrgID:     "org:1",
		Action:    types.ApprovalActionTenantDecommission,
		Requester: "user-alice",
	}
	cases := []struct {
		name     string
		platform *fakePlatformChecker
		roles    RoleResolver
		approver string
		wantErr  error
	}{
		{name: "org_creator allowed", platform: &fakePlatformChecker{ok: true}, roles: fakeRoleResolver{}, approver: "user-bob"},
		{name: "org-admin allowed when platform check denies", platform: &fakePlatformChecker{}, roles: fakeRoleResolver{role: types.RoleOrgAdmin}, approver: "user-bob"},
		{name: "platform-engineer allowed when platform check denies", platform: &fakePlatformChecker{}, roles: fakeRoleResolver{role: types.RolePlatformEngineer}, approver: "user-bob"},
		{name: "developer denied", platform: &fakePlatformChecker{}, roles: fakeRoleResolver{role: types.RoleDeveloper}, approver: "user-bob", wantErr: ErrApproverRole},
		{name: "non-member denied", platform: &fakePlatformChecker{}, roles: fakeRoleResolver{}, approver: "user-bob", wantErr: ErrApproverRole},
		{name: "org-admin allowed without platform seam", roles: fakeRoleResolver{role: types.RoleOrgAdmin}, approver: "user-bob"},
		{name: "denied with neither seam granting", platform: &fakePlatformChecker{}, approver: "user-bob", wantErr: ErrApproverRole},
		{name: "requester cannot self-decide even as org_creator", platform: &fakePlatformChecker{ok: true}, roles: fakeRoleResolver{role: types.RoleOrgAdmin}, approver: "user-alice", wantErr: ErrSelfApproval},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{roles: tc.roles}
			if tc.platform != nil {
				s.WithPlatformChecker(tc.platform)
			}
			err := s.authorizeLifecycleApprover(context.Background(), req, tc.approver)
			if tc.wantErr == nil && err != nil {
				t.Fatalf("approver should be authorized: %v", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidLifecycleAction(t *testing.T) {
	if !ValidLifecycleAction(types.ApprovalActionTenantZoneVend) {
		t.Error("tenant_zone.vend should be valid")
	}
	if !ValidLifecycleAction(types.ApprovalActionTenantZoneDecommission) {
		t.Error("tenant_zone.decommission should be valid")
	}
	if ValidLifecycleAction("bogus.action") {
		t.Error("unknown action must be rejected")
	}
}
