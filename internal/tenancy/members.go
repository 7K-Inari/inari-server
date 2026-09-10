package tenancy

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/types"
)

// teamByName resolves a team and the org role its membership grants
// (persisted on the teams row since migration 0011).
func (s *Service) teamByName(ctx context.Context, orgID, teamName string) (*types.Team, types.Role, error) {
	team, err := s.store.GetTeamByName(ctx, s.db.Pool, orgID, teamName)
	if err != nil {
		return nil, "", err
	}
	return team, team.Role, nil
}

// AddMember validates the subject, joins them to the Keycloak org + team
// group, then records the membership with audit + outbox in one tx.
func (s *Service) AddMember(ctx context.Context, actor, slug, teamName, userID string) error {
	user, err := s.idp.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return err
	}
	team, role, err := s.teamByName(ctx, org.ID, teamName)
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
			UserID: userID, OrgID: org.ID, TeamID: team.ID, Role: role,
		})
		if err != nil {
			return err
		}
		if !inserted {
			return nil
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: org.ID, Actor: actor, Action: "membership.added", ObjectType: "user", ObjectID: userID,
			Payload: []byte(fmt.Sprintf(`{"teamId":%q,"team":%q,"role":%q}`, team.ID, team.Name, role)),
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, org.ID, types.EventMembershipAdded, types.MembershipPayload{
			OrgID: org.ID, TeamID: team.ID, UserID: userID, Role: role,
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
	team, role, err := s.teamByName(ctx, org.ID, teamName)
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
			OrgID: org.ID, TeamID: team.ID, UserID: userID, Role: role,
		})
	})
}

// ListMembers returns the team's members for the console.
func (s *Service) ListMembers(ctx context.Context, orgID, teamID string) ([]MemberView, error) {
	return s.store.ListMembers(ctx, s.db.Pool, orgID, teamID)
}

// ListOrgMembers returns the org-wide member view (highest role + teams).
func (s *Service) ListOrgMembers(ctx context.Context, orgID string) ([]OrgMemberView, error) {
	return s.store.ListOrgMembers(ctx, s.db.Pool, orgID)
}

// SetMemberRole sets a user's org role by placing them in the role's anchor
// team and removing them from every other anchor team. Emits member.added
// for new members and member.role_changed for existing ones.
func (s *Service) SetMemberRole(ctx context.Context, actor, slug, userID string, role types.Role) error {
	anchorName, ok := AnchorTeamForRole(role)
	if !ok {
		return fmt.Errorf("tenancy: invalid role %q", role)
	}
	user, err := s.idp.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return err
	}
	anchor, err := s.ensureTeam(ctx, actor, org, anchorName, role)
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
		inserted, err := s.store.AddMembership(ctx, tx, &types.Membership{
			UserID: userID, OrgID: org.ID, TeamID: anchor.ID, Role: role,
		})
		if err != nil {
			return err
		}
		for _, m := range removed {
			removedRow, err := s.store.RemoveMembership(ctx, tx, &types.Membership{
				UserID: userID, OrgID: org.ID, TeamID: m.TeamID,
			})
			if err != nil {
				return err
			}
			if removedRow {
				if err := audit.AppendOutbox(ctx, tx, org.ID, types.EventMembershipRemoved, types.MembershipPayload{
					OrgID: org.ID, TeamID: m.TeamID, UserID: userID, Role: m.Role,
				}); err != nil {
					return err
				}
			}
		}
		if inserted {
			if err := audit.AppendOutbox(ctx, tx, org.ID, types.EventMembershipAdded, types.MembershipPayload{
				OrgID: org.ID, TeamID: anchor.ID, UserID: userID, Role: role,
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
				Payload: []byte(fmt.Sprintf(`{"role":%q,"team":%q}`, role, anchor.Name)),
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
				OrgID: org.ID, TeamID: m.TeamID, UserID: userID, Role: m.Role,
			}); err != nil {
				return err
			}
		}
		return nil
	})
}
