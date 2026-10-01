package tenancy

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// SyncTeamMembers projects a Keycloak team group's membership into the DB
// users/memberships projection (authz.TeamMemberProjector seam, M1.W1):
// reflected/brokered members appear in the console member list within one
// OrgTeamSync interval. Keycloak group membership is the source of truth;
// the DB rows are derived state, converged on every reconcile pass.
//
// Single-writer discipline: this projection must NOT emit membership
// outbox events (or audit rows). The OrgTeamSync reconciler converges the
// OpenFGA tuples for reflected membership itself; the outbox tuple writer
// stays scoped to the invite API (AddMember/SetMemberRole/RemoveMember),
// so emitting events here would double the tuple writes.
//
// Idempotent and conflict-safe against the invite flow: user and
// membership writes are same-PK upserts (ON CONFLICT DO NOTHING), so an
// invite-created row is never modified and a row granting another role via
// another team is never downgraded (role_id is part of the membership PK).
// A stale-read race with the invite flow converges on the next reconcile
// tick — the same accepted trade-off as the tuple convergence
// (ADR-0003/0004).
func (s *Service) SyncTeamMembers(ctx context.Context, ref authz.TeamGroupRef, members []*types.User) error {
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		keep := make([]string, 0, len(members))
		for _, u := range members {
			if u == nil || u.ID == "" {
				continue
			}
			if err := s.store.UpsertUser(ctx, tx, u); err != nil {
				return err
			}
			// Same semantics as AddMember: role reference denormalized from the
			// team, conflict on (user, org, role_id) is a no-op.
			if _, err := s.store.AddMembership(ctx, tx, &types.Membership{
				UserID: u.ID, OrgID: ref.OrgID, TeamID: ref.TeamID, RoleID: ref.RoleID,
			}); err != nil {
				return err
			}
			keep = append(keep, u.ID)
		}
		// Delete-stale, scoped to the reconciled team only: rows on other
		// teams (including higher-role anchor teams) are untouched. Also
		// delete rows whose role_id no longer matches the team's current
		// role_id, so a team role change revokes the old role instead of
		// leaving a duplicate membership row (B8).
		return s.store.RemoveStaleTeamMemberships(ctx, tx, ref.TeamID, ref.RoleID, keep)
	})
}

// RemoveStaleTeamMemberships deletes every membership row of the team that
// should no longer exist: the user left the Keycloak group (not in keep) or
// the team's role_id changed and the row reflects the old role. Scoped to
// team_id, so rows granting other roles via other teams survive.
func (s *Store) RemoveStaleTeamMemberships(ctx context.Context, q db.Querier, teamID, roleID string, keep []string) error {
	const sql = `DELETE FROM memberships WHERE team_id = $1 AND (user_id <> ALL($2) OR role_id <> $3)`
	_, err := q.Exec(ctx, sql, teamID, keep, roleID)
	return err
}
