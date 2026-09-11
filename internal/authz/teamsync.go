package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// TeamGroupRef pairs a team with the Keycloak group whose membership grants
// team membership (tenant-<slug>/<team>).
type TeamGroupRef struct {
	TeamID    string
	GroupPath string
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

// OrgTeamSync reconciles Keycloak org-team group membership to
// team:<id>#member tuples for every tenant (M6.W7, ADR-0004). It is the
// convergence mechanism for IdP-brokered managed members, who never pass
// through the inline invite path. Consistency window: one Run interval.
type OrgTeamSync struct {
	store   Store
	members GroupMemberLister
	teams   TeamGroupLister
}

func NewOrgTeamSync(store Store, members GroupMemberLister, teams TeamGroupLister) *OrgTeamSync {
	return &OrgTeamSync{store: store, members: members, teams: teams}
}

// SyncOnce reconciles every team group in both directions: missing members
// get tuples, tuples for principals no longer in the Keycloak group are
// deleted. A failing group is logged and skipped so one tenant cannot
// starve the others; the joined error is returned for the Run loop's log.
// Idempotent.
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
		if err := reconcileGroup(ctx, s.store, s.members, g.GroupPath, TeamObject(g.TeamID), RelationMember); err != nil {
			slog.Warn("org team sync", "group", g.GroupPath, "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", g.GroupPath, err))
		}
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
