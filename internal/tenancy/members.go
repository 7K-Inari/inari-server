package tenancy

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/types"
)

// teamRole maps the default team name to the org role it grants; membership
// rows record the role so HighestRole keeps working without a teams join.
func (s *Service) teamByName(ctx context.Context, orgID, teamName string) (*types.Team, types.Role, error) {
	team, err := s.store.GetTeamByName(ctx, s.db.Pool, orgID, teamName)
	if err != nil {
		return nil, "", err
	}
	role := types.RoleViewer
	for _, dt := range DefaultTeams {
		if dt.Name == team.Name {
			role = dt.Role
		}
	}
	return team, role, nil
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
	exists, err := s.store.MembershipExists(ctx, s.db.Pool, userID, org.ID, team.ID)
	if err != nil {
		return err
	}
	if exists {
		return nil
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
		if err := s.store.AddMembership(ctx, tx, &types.Membership{
			UserID: userID, OrgID: org.ID, TeamID: team.ID, Role: role,
		}); err != nil {
			return err
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
	exists, err := s.store.MembershipExists(ctx, s.db.Pool, userID, org.ID, team.ID)
	if err != nil {
		return err
	}
	// Keycloak removal is idempotent; skip the DB row + outbox event when no
	// membership was recorded so a repeated DELETE can't emit a removal event
	// for an OpenFGA tuple that no longer exists.
	if err := s.idp.RemoveGroupMember(ctx, team.KeycloakGroupPath, userID); err != nil {
		return fmt.Errorf("tenancy: remove group member: %w", err)
	}
	if !exists {
		return nil
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.RemoveMembership(ctx, tx, &types.Membership{
			UserID: userID, OrgID: org.ID, TeamID: team.ID,
		}); err != nil {
			return err
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
