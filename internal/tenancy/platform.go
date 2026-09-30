package tenancy

import (
	"context"
	"fmt"
	"slices"

	"github.com/7K-Inari/inari-server/internal/types"
)

// PlatformAdminView is the console view of one platform admin: the Keycloak
// user profile of a member of the platform admin group.
type PlatformAdminView struct {
	UserID      string `json:"userId"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
}

// platformAuditOrgID scopes platform-level audit events (catalog precedent:
// platform actions have no tenant org).
const platformAuditOrgID = "platform"

// ListPlatformAdmins returns the members of the platform admin group with
// their user profiles. The group is tiny, so per-member profile resolution
// is acceptable.
func (s *Service) ListPlatformAdmins(ctx context.Context, group string) ([]PlatformAdminView, error) {
	ids, err := s.idp.ListGroupMembers(ctx, group)
	if err != nil {
		return nil, err
	}
	out := make([]PlatformAdminView, 0, len(ids))
	for _, id := range ids {
		user, err := s.idp.GetUser(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, PlatformAdminView{UserID: user.ID, Email: user.Email, DisplayName: user.DisplayName})
	}
	return out, nil
}

// GrantPlatformAdmin adds the subject (Keycloak UUID or email) to the
// platform admin group and records the grant. It deliberately writes no
// OpenFGA tuple: PlatformGroupSync (ADR-0003) is the single writer of
// platform:inari org_creator tuples and converges within one sync interval.
// Re-granting an existing member is a silent no-op (no duplicate audit
// row); a concurrent double-grant can still race past the membership check
// and audit twice — harmless and bounded by the group's tiny size.
func (s *Service) GrantPlatformAdmin(ctx context.Context, actor, group, subject string) error {
	user, err := s.resolveMemberSubject(ctx, subject)
	if err != nil {
		return err
	}
	members, err := s.idp.ListGroupMembers(ctx, group)
	if err != nil {
		return fmt.Errorf("tenancy: grant platform admin: %w", err)
	}
	if slices.Contains(members, user.ID) {
		return nil
	}
	if err := s.idp.AddGroupMember(ctx, group, user.ID); err != nil {
		return fmt.Errorf("tenancy: grant platform admin: %w", err)
	}
	return s.audit.Record(ctx, s.db.Pool, &types.AuditEvent{
		OrgID: platformAuditOrgID, Actor: actor, Action: "platform.admin.granted", ObjectType: "user", ObjectID: user.ID,
		Payload: []byte(fmt.Sprintf(`{"email":%q,"group":%q}`, user.Email, group)),
	})
}

// RevokePlatformAdmin removes the subject from the platform admin group.
// Keycloak removal is idempotent, so revoking a non-member succeeds (and is
// a silent no-op — see GrantPlatformAdmin). FGA org_creator tuples converge
// via PlatformGroupSync.
func (s *Service) RevokePlatformAdmin(ctx context.Context, actor, group, subject string) error {
	user, err := s.resolveMemberSubject(ctx, subject)
	if err != nil {
		return err
	}
	members, err := s.idp.ListGroupMembers(ctx, group)
	if err != nil {
		return fmt.Errorf("tenancy: revoke platform admin: %w", err)
	}
	if !slices.Contains(members, user.ID) {
		return nil
	}
	if err := s.idp.RemoveGroupMember(ctx, group, user.ID); err != nil {
		return fmt.Errorf("tenancy: revoke platform admin: %w", err)
	}
	return s.audit.Record(ctx, s.db.Pool, &types.AuditEvent{
		OrgID: platformAuditOrgID, Actor: actor, Action: "platform.admin.revoked", ObjectType: "user", ObjectID: user.ID,
		Payload: []byte(fmt.Sprintf(`{"email":%q,"group":%q}`, user.Email, group)),
	})
}
