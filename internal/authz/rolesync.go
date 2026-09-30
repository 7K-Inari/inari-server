// OrgRoleSync reconciles the per-permission organization tuples from the DB
// teams/roles projection (ADR-0013): the TupleWriter applies outbox deltas,
// this reconciler converges drift in both directions and performs the
// post-model-swap repopulation at startup. Keycloak group membership feeds
// team#member tuples via OrgTeamSync; this reconciler only manages
// team:<id>#member → organization:<id>#<permission> userset tuples, which
// derive deterministically from the roles table.
package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// legacyOrgRelations are the retired hierarchical organization relations
// (pre-ADR-0013 model). Tuples under them are swept once at startup,
// best-effort; reads against the new model tolerate "relation not found".
var legacyOrgRelations = []string{"admin", "platform_engineer", "developer", "viewer"}

// OrgRoleSync converges organization permission tuples with the DB
// teams/roles projection for every tenant.
type OrgRoleSync struct {
	store Store
	teams TeamGroupLister
}

func NewOrgRoleSync(store Store, teams TeamGroupLister) *OrgRoleSync {
	return &OrgRoleSync{store: store, teams: teams}
}

// SyncOnce runs one full convergence pass: legacy-relation sweep plus the
// desired-vs-actual diff of every permission relation of every org.
// Idempotent; a failing org is logged and skipped so one tenant cannot
// starve the others.
func (s *OrgRoleSync) SyncOnce(ctx context.Context) error {
	groups, err := s.teams.ListTeamGroups(ctx)
	if err != nil {
		return err
	}
	// desired[orgID][relation] = set of team member usersets.
	desired := map[string]map[string]map[string]bool{}
	for _, g := range groups {
		for _, p := range g.Permissions {
			rel, ok := PermissionRelation(p)
			if !ok {
				continue
			}
			if desired[g.OrgID] == nil {
				desired[g.OrgID] = map[string]map[string]bool{}
			}
			if desired[g.OrgID][rel] == nil {
				desired[g.OrgID][rel] = map[string]bool{}
			}
			desired[g.OrgID][rel][TeamMemberUserset(g.TeamID)] = true
		}
	}
	var errs []error
	for orgID, rels := range desired {
		obj := OrgObject(orgID)
		if err := s.sweepLegacy(ctx, obj); err != nil {
			slog.Warn("org role sync legacy sweep", "org", orgID, "error", err)
			errs = append(errs, fmt.Errorf("%s legacy sweep: %w", orgID, err))
		}
		if err := s.convergeOrg(ctx, obj, rels); err != nil {
			slog.Warn("org role sync", "org", orgID, "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", orgID, err))
		}
	}
	return errors.Join(errs...)
}

// sweepLegacy deletes every tuple under the retired hierarchical relations
// of one org. Best-effort: relation-not-found errors (model already
// swapped) are tolerated.
func (s *OrgRoleSync) sweepLegacy(ctx context.Context, orgObject string) error {
	var errs []error
	for _, rel := range legacyOrgRelations {
		tuples, err := s.store.ReadTuples(ctx, orgObject, rel)
		if err != nil {
			if isRelationNotFoundErr(err) {
				continue
			}
			errs = append(errs, err)
			continue
		}
		if len(tuples) == 0 {
			continue
		}
		if err := s.store.DeleteTuples(ctx, tuples); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// convergeOrg diffs desired vs actual for every permission relation of one
// org and writes/deletes the difference. Relations with no desired tuples
// are still read so stray actual tuples are retracted.
func (s *OrgRoleSync) convergeOrg(ctx context.Context, orgObject string, desired map[string]map[string]bool) error {
	var errs []error
	for _, p := range PermissionCatalog() {
		rel, _ := PermissionRelation(p.Slug)
		actual, err := s.store.ReadTuples(ctx, orgObject, rel)
		if err != nil {
			errs = append(errs, fmt.Errorf("read %s: %w", rel, err))
			continue
		}
		want := desired[rel]
		var add, del []Tuple
		seen := map[string]bool{}
		for _, t := range actual {
			seen[t.User] = true
			if !want[t.User] {
				del = append(del, t)
			}
		}
		for userset := range want {
			if !seen[userset] {
				add = append(add, Tuple{User: userset, Relation: rel, Object: orgObject})
			}
		}
		if len(del) > 0 {
			if err := s.store.DeleteTuples(ctx, del); err != nil {
				errs = append(errs, fmt.Errorf("delete %s: %w", rel, err))
				continue
			}
		}
		if len(add) > 0 {
			if err := s.store.WriteTuples(ctx, add); err != nil {
				errs = append(errs, fmt.Errorf("write %s: %w", rel, err))
			}
		}
	}
	return errors.Join(errs...)
}

// isRelationNotFoundErr reports whether err is OpenFGA's "relation not
// found" (reading a relation the current model no longer defines).
func isRelationNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "relation") &&
		(strings.Contains(msg, "not found") || strings.Contains(msg, "undefined"))
}

// Run reconciles on a ticker until ctx is cancelled; errors are logged, not
// fatal. Mirrors OrgTeamSync.Run (non-positive interval falls back to 30s).
func (s *OrgRoleSync) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if err := s.SyncOnce(ctx); err != nil {
		slog.Warn("org role sync", "error", err)
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := s.SyncOnce(ctx); err != nil {
				slog.Warn("org role sync", "error", err)
			}
		}
	}
}
