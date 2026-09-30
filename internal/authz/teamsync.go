package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/7K-Inari/inari-server/internal/types"
)

// TeamGroupRef pairs a team with the Keycloak group whose membership grants
// team membership (tenant-<slug>/<team>). OrgID and RoleID are what the DB
// membership projection denormalizes onto membership rows; Permissions is
// the team's role bundle snapshot used by the OrgRoleSync tuple reconciler.
type TeamGroupRef struct {
	TeamID      string
	OrgID       string
	RoleID      string
	Permissions []string
	GroupPath   string
}

// TeamGroupLister enumerates every server-owned team group across all
// tenants (tenancy.Service seam; the teams projection is the source of
// group paths, Keycloak is the source of membership).
type TeamGroupLister interface {
	ListTeamGroups(ctx context.Context) ([]TeamGroupRef, error)
}

// TeamGroupListerFunc adapts a function to TeamGroupLister.
type TeamGroupListerFunc func(ctx context.Context) ([]TeamGroupRef, error)

func (f TeamGroupListerFunc) ListTeamGroups(ctx context.Context) ([]TeamGroupRef, error) {
	return f(ctx)
}

// GroupUserLister lists the full user profiles of a Keycloak group's
// members (tenancy.IdentityProvider seam). User IDs feed FGA tuple
// convergence; the profiles feed the DB membership projection, so one
// Keycloak read per group drives both.
type GroupUserLister interface {
	ListGroupMemberUsers(ctx context.Context, groupPath string) ([]*types.User, error)
}

// TeamMemberProjector projects a Keycloak team group's membership into the
// DB users/memberships projection (tenancy.Service seam). Implementations
// must be idempotent and must NOT emit membership outbox events: this
// reconciler converges the FGA tuples itself, and the outbox tuple writer
// stays scoped to the invite API (single-writer discipline, ADR-0004).
type TeamMemberProjector interface {
	SyncTeamMembers(ctx context.Context, ref TeamGroupRef, members []*types.User) error
}

// OrgTeamSync reconciles Keycloak org-team group membership to
// team:<id>#member tuples AND to the DB users/memberships projection for
// every tenant (M6.W7 + M1.W1, ADR-0004). It is the convergence mechanism
// for IdP-brokered managed members, who never pass through the inline
// invite path: reflected members appear in the console member list within
// one Run interval.
type OrgTeamSync struct {
	store      Store
	users      GroupUserLister
	teams      TeamGroupLister
	projection TeamMemberProjector
}

func NewOrgTeamSync(store Store, users GroupUserLister, teams TeamGroupLister, projection TeamMemberProjector) *OrgTeamSync {
	return &OrgTeamSync{store: store, users: users, teams: teams, projection: projection}
}

// SyncOnce reconciles every team group in both directions — FGA tuples and
// DB projection rows: missing members get tuples + rows, tuples/rows for
// principals no longer in the Keycloak group are deleted. A failing group
// is logged and skipped so one tenant cannot starve the others; the joined
// error is returned for the Run loop's log. Idempotent.
func (s *OrgTeamSync) SyncOnce(ctx context.Context) error {
	groups, err := s.teams.ListTeamGroups(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, g := range groups {
		if g.GroupPath == "" {
			continue
		}
		if err := s.reconcileTeamGroup(ctx, g); err != nil {
			slog.Warn("org team sync", "group", g.GroupPath, "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", g.GroupPath, err))
		}
	}
	return errors.Join(errs...)
}

// reconcileTeamGroup fetches the group's members once and converges both
// derived states from it. Tuple convergence and DB projection are
// independent: a failure in one does not suppress the other, and both
// retry on the next tick.
func (s *OrgTeamSync) reconcileTeamGroup(ctx context.Context, g TeamGroupRef) error {
	users, err := s.users.ListGroupMemberUsers(ctx, g.GroupPath)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(users))
	for _, u := range users {
		ids = append(ids, u.ID)
	}
	var errs []error
	if err := reconcileMembers(ctx, s.store, ids, TeamObject(g.TeamID), RelationMember); err != nil {
		errs = append(errs, err)
	}
	if err := s.projection.SyncTeamMembers(ctx, g, users); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Run reconciles on a ticker until ctx is cancelled; errors are logged, not
// fatal. A non-positive interval (misconfiguration) falls back to 30s
// instead of panicking in time.NewTicker.
func (s *OrgTeamSync) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if err := s.SyncOnce(ctx); err != nil {
		slog.Warn("org team sync", "error", err)
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := s.SyncOnce(ctx); err != nil {
				slog.Warn("org team sync", "error", err)
			}
		}
	}
}
