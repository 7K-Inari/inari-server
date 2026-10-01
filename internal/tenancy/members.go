package tenancy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/types"
)

// teamByName resolves a team and the org role its membership grants.
func (s *Service) teamByName(ctx context.Context, orgID, teamName string) (*types.Team, error) {
	return s.store.GetTeamByName(ctx, s.db.Pool, orgID, teamName)
}

// resolveMemberSubject resolves a member subject: a Keycloak user UUID, or a
// user email (the console's invite form submits an email). It returns the
// user profile; callers must use user.ID for all subsequent operations.
func (s *Service) resolveMemberSubject(ctx context.Context, subject string) (*types.User, error) {
	user, err := s.idp.GetUser(ctx, subject)
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, ErrUserNotFound) || !strings.Contains(subject, "@") {
		return nil, err
	}
	return s.idp.GetUserByEmail(ctx, subject)
}

// AddMember validates the subject, joins them to the Keycloak org + team
// group, then records the membership with audit + outbox in one tx.
func (s *Service) AddMember(ctx context.Context, actor, slug, teamName, userID string) error {
	user, err := s.resolveMemberSubject(ctx, userID)
	if err != nil {
		return err
	}
	userID = user.ID
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return err
	}
	team, err := s.teamByName(ctx, org.ID, teamName)
	if err != nil {
		return err
	}
	if err := s.idp.AddOrganizationMember(ctx, org.KeycloakOrgID, userID); err != nil {
		return fmt.Errorf("tenancy: add org member: %w", err)
	}
	if err := s.idp.AddGroupMember(ctx, team.KeycloakGroupPath, userID); err != nil {
		return fmt.Errorf("tenancy: add group member: %w", err)
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.UpsertUser(ctx, tx, user); err != nil {
			return err
		}
		// The unique PK serializes concurrent adds: exactly one tx inserts the
		// row, and only that tx emits audit + outbox. This keeps OpenFGA safe
		// from duplicate membership tuples (which would stall the dispatcher).
		inserted, err := s.store.AddMembership(ctx, tx, &types.Membership{
			UserID: userID, OrgID: org.ID, TeamID: team.ID, RoleID: team.RoleID,
		})
		if err != nil {
			return err
		}
		if !inserted {
			return nil
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: org.ID, Actor: actor, Action: "membership.added", ObjectType: "user", ObjectID: userID,
			Payload: []byte(fmt.Sprintf(`{"teamId":%q,"team":%q,"role":%q}`, team.ID, team.Name, team.RoleName)),
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, org.ID, types.EventMembershipAdded, types.MembershipPayload{
			OrgID: org.ID, TeamID: team.ID, UserID: userID, RoleID: team.RoleID,
		})
	})
}

// RemoveMember removes the group membership and records the removal with
// audit + outbox in one tx.
func (s *Service) RemoveMember(ctx context.Context, actor, slug, teamName, userID string) error {
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return err
	}
	team, err := s.teamByName(ctx, org.ID, teamName)
	if err != nil {
		return err
	}
	// Keycloak removal is idempotent; run it even when no DB row exists (the
	// group join may have landed while the recording tx crashed).
	if err := s.idp.RemoveGroupMember(ctx, team.KeycloakGroupPath, userID); err != nil {
		return fmt.Errorf("tenancy: remove group member: %w", err)
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		// RowsAffected serializes concurrent removes: exactly one tx deletes
		// the row and emits audit + outbox, so OpenFGA never sees a delete for
		// an already-absent tuple.
		removed, err := s.store.RemoveMembership(ctx, tx, &types.Membership{
			UserID: userID, OrgID: org.ID, TeamID: team.ID,
		})
		if err != nil {
			return err
		}
		if !removed {
			return nil
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: org.ID, Actor: actor, Action: "membership.removed", ObjectType: "user", ObjectID: userID,
			Payload: []byte(fmt.Sprintf(`{"teamId":%q,"team":%q}`, team.ID, team.Name)),
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, org.ID, types.EventMembershipRemoved, types.MembershipPayload{
			OrgID: org.ID, TeamID: team.ID, UserID: userID, RoleID: team.RoleID,
		})
	})
}

// ListMembers returns the team's members for the console. A non-empty
// query filters by case-insensitive email substring.
func (s *Service) ListMembers(ctx context.Context, orgID, teamID, query string) ([]MemberView, error) {
	return s.store.ListMembers(ctx, s.db.Pool, orgID, teamID, query)
}

// ListOrgMembers returns the org-wide member view (highest role + teams). A
// non-empty query filters by case-insensitive email substring.
func (s *Service) ListOrgMembers(ctx context.Context, orgID, query string) ([]OrgMemberView, error) {
	return s.store.ListOrgMembers(ctx, s.db.Pool, orgID, query)
}

// SetMemberRole sets a user's org role by placing them in the role's anchor
// team (built-in anchors for built-ins, a team named after a custom role —
// materialized lazily) and removing them from every other team. Emits
// member.added for new members and member.role_changed for existing ones.
func (s *Service) SetMemberRole(ctx context.Context, actor, slug, userID, roleID string) error {
	user, err := s.resolveMemberSubject(ctx, userID)
	if err != nil {
		return err
	}
	userID = user.ID
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return err
	}
	role, err := s.store.GetRoleByID(ctx, s.db.Pool, org.ID, roleID)
	if errors.Is(err, ErrRoleNotFound) {
		role, err = s.store.GetRoleByName(ctx, s.db.Pool, org.ID, roleID)
	}
	if err != nil {
		return err
	}
	anchor, err := s.ensureTeam(ctx, actor, org, AnchorTeamForRole(role), role)
	if err != nil {
		return err
	}
	current, err := s.store.ListMembershipsWithPaths(ctx, s.db.Pool, org.ID, userID)
	if err != nil {
		return err
	}
	// Keycloak mutations first (idempotent): join org + anchor group, leave
	// every other team — PUT defines the caller's single org role.
	if err := s.idp.AddOrganizationMember(ctx, org.KeycloakOrgID, userID); err != nil {
		return fmt.Errorf("tenancy: add org member: %w", err)
	}
	if err := s.idp.AddGroupMember(ctx, anchor.KeycloakGroupPath, userID); err != nil {
		return fmt.Errorf("tenancy: add group member: %w", err)
	}
	var removed []MembershipWithPath
	for _, m := range current {
		if m.TeamID == anchor.ID {
			continue
		}
		if m.GroupPath != "" {
			if err := s.idp.RemoveGroupMember(ctx, m.GroupPath, userID); err != nil {
				return fmt.Errorf("tenancy: remove group member: %w", err)
			}
		}
		removed = append(removed, m)
	}
	isNew := len(current) == 0
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.UpsertUser(ctx, tx, user); err != nil {
			return err
		}
		// Remove other-team rows first: memberships are keyed
		// (user, org, role_id), so an insert would conflict (and be
		// skipped) when the user already holds the same role via
		// another team — leaving them with no row at all.
		for _, m := range removed {
			removedRow, err := s.store.RemoveMembership(ctx, tx, &types.Membership{
				UserID: userID, OrgID: org.ID, TeamID: m.TeamID,
			})
			if err != nil {
				return err
			}
			if removedRow {
				if err := audit.AppendOutbox(ctx, tx, org.ID, types.EventMembershipRemoved, types.MembershipPayload{
					OrgID: org.ID, TeamID: m.TeamID, UserID: userID, RoleID: m.RoleID,
				}); err != nil {
					return err
				}
			}
		}
		// Record the membership using the anchor team's actual role_id. If the
		// anchor team has been remapped via PUT /rbac/mappings, the effective
		// role is the team's current role, not the requested role name
		// (ADR-0013). This prevents a membership row whose role_id disagrees
		// with teams.role_id, which the projection would otherwise "correct"
		// by adding a duplicate row (B8).
		inserted, err := s.store.AddMembership(ctx, tx, &types.Membership{
			UserID: userID, OrgID: org.ID, TeamID: anchor.ID, RoleID: anchor.RoleID,
		})
		if err != nil {
			return err
		}
		if inserted {
			if err := audit.AppendOutbox(ctx, tx, org.ID, types.EventMembershipAdded, types.MembershipPayload{
				OrgID: org.ID, TeamID: anchor.ID, UserID: userID, RoleID: anchor.RoleID,
			}); err != nil {
				return err
			}
		}
		if inserted || len(removed) > 0 {
			action := "member.role_changed"
			if isNew {
				action = "member.added"
			}
			if err := s.audit.Record(ctx, tx, &types.AuditEvent{
				OrgID: org.ID, Actor: actor, Action: action, ObjectType: "user", ObjectID: userID,
				Payload: []byte(fmt.Sprintf(`{"role":%q,"team":%q}`, anchor.RoleName, anchor.Name)),
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

// RemoveOrgMember removes a user from all teams and the Keycloak org,
// recording member.removed with one outbox event per removed tuple.
func (s *Service) RemoveOrgMember(ctx context.Context, actor, slug, userID string) error {
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return err
	}
	current, err := s.store.ListMembershipsWithPaths(ctx, s.db.Pool, org.ID, userID)
	if err != nil {
		return err
	}
	// Keycloak removals are idempotent; run them even with no DB rows (the
	// group joins may have landed while the recording tx crashed).
	for _, m := range current {
		if m.GroupPath != "" {
			if err := s.idp.RemoveGroupMember(ctx, m.GroupPath, userID); err != nil {
				return fmt.Errorf("tenancy: remove group member: %w", err)
			}
		}
	}
	if err := s.idp.RemoveOrganizationMember(ctx, org.KeycloakOrgID, userID); err != nil {
		return fmt.Errorf("tenancy: remove org member: %w", err)
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		removed, err := s.store.RemoveMembershipsForUser(ctx, tx, org.ID, userID)
		if err != nil {
			return err
		}
		if len(removed) == 0 {
			return nil
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: org.ID, Actor: actor, Action: "member.removed", ObjectType: "user", ObjectID: userID,
			Payload: []byte(fmt.Sprintf(`{"teams":%d}`, len(removed))),
		}); err != nil {
			return err
		}
		for _, m := range removed {
			if err := audit.AppendOutbox(ctx, tx, org.ID, types.EventMembershipRemoved, types.MembershipPayload{
				OrgID: org.ID, TeamID: m.TeamID, UserID: userID, RoleID: m.RoleID,
			}); err != nil {
				return err
			}
		}
		return nil
	})
}
