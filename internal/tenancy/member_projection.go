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
// invite-created row is never modified and an existing higher-role row is
// never downgraded (roles are part of the membership PK). A stale-read
// race with the invite flow converges on the next reconcile tick — the
// same accepted trade-off as the tuple convergence (ADR-0003/0004).
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
			// Same semantics as AddMember: role denormalized from the team,
			// conflict on (user, org, role) is a no-op.
			if _, err := s.store.AddMembership(ctx, tx, &types.Membership{
				UserID: u.ID, OrgID: ref.OrgID, TeamID: ref.TeamID, Role: ref.Role,
			}); err != nil {
				return err
			}
			keep = append(keep, u.ID)
		}
		// Delete-stale, scoped to the reconciled team only: rows on other
		// teams (including higher-role anchor teams) are untouched.
		return s.store.RemoveMembershipsNotIn(ctx, tx, ref.TeamID, keep)
	})
}

// RemoveMembershipsNotIn deletes every membership row of the team whose
// user is no longer in the Keycloak group (the keep set). Scoped to
// team_id, so rows granting other roles via other teams survive.
func (s *Store) RemoveMembershipsNotIn(ctx context.Context, q db.Querier, teamID string, keep []string) error {
	const sql = `DELETE FROM memberships WHERE team_id = $1 AND user_id <> ALL($2)`
	_, err := q.Exec(ctx, sql, teamID, keep)
	return err
}
