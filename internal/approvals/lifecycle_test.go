package approvals

import (
	"context"
	"errors"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

type fakePlatformChecker struct{ ok bool }

func (f fakePlatformChecker) Check(context.Context, string, string, string) (bool, error) {
	return f.ok, nil
}

type fakePermissionResolver struct {
	ok  bool
	err error
}

func (f fakePermissionResolver) HasPermission(context.Context, string, string, string) (bool, error) {
	return f.ok, f.err
}

// TestAuthorizeLifecycleApprover pins the platform-admin policy on lifecycle
// decisions (issue #74): a tenant freeze sweeps the org's FGA tuples before
// the approval is decided, so authorization must accept a platform
// org_creator OR a DB-backed platform-operations permission.
func TestAuthorizeLifecycleApprover(t *testing.T) {
	req := &types.ApprovalRequest{
		OrgID:     "org:1",
		Action:    types.ApprovalActionTenantDecommission,
		Requester: "user-alice",
	}
	cases := []struct {
		name     string
		platform *fakePlatformChecker
		roles    PermissionResolver
		approver string
		wantErr  error
	}{
		{name: "org_creator allowed", platform: &fakePlatformChecker{ok: true}, roles: fakePermissionResolver{}, approver: "user-bob"},
		{name: "platform-operations permission allowed when platform check denies", platform: &fakePlatformChecker{}, roles: fakePermissionResolver{ok: true}, approver: "user-bob"},
		{name: "member without floor denied", platform: &fakePlatformChecker{}, roles: fakePermissionResolver{}, approver: "user-bob", wantErr: ErrApproverRole},
		{name: "non-member denied", platform: &fakePlatformChecker{}, roles: fakePermissionResolver{}, approver: "user-bob", wantErr: ErrApproverRole},
		{name: "permission allowed without platform seam", roles: fakePermissionResolver{ok: true}, approver: "user-bob"},
		{name: "denied with neither seam granting", platform: &fakePlatformChecker{}, approver: "user-bob", wantErr: ErrApproverRole},
		{name: "requester cannot self-decide even as org_creator", platform: &fakePlatformChecker{ok: true}, roles: fakePermissionResolver{ok: true}, approver: "user-alice", wantErr: ErrSelfApproval},
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
