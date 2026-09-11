package authz

import (
	"context"
	"log/slog"
	"time"
)

// GroupMemberLister lists the Keycloak user ids of the platform admin group
// (tenancy.IdentityProvider seam).
type GroupMemberLister interface {
	ListGroupMembers(ctx context.Context, groupPath string) ([]string, error)
}

// PlatformGroupSync reconciles the Keycloak platform admin group to
// platform:inari org_creator tuples (M1.W2, ADR-0003). It is the single
// writer for org_creator tuples; superuser is out of scope. Consistency
// window: one Run interval after a group membership change.
type PlatformGroupSync struct {
	store   Store
	members GroupMemberLister
	group   string
}

func NewPlatformGroupSync(store Store, members GroupMemberLister, group string) *PlatformGroupSync {
	return &PlatformGroupSync{store: store, members: members, group: group}
}

// SyncOnce reconciles the platform admin group to org_creator tuples on
// platform:inari. Idempotent.
func (s *PlatformGroupSync) SyncOnce(ctx context.Context) error {
	return reconcileGroup(ctx, s.store, s.members, s.group, ObjectPlatform, RelationOrgCreator)
}

// reconcileGroup diffs Keycloak group membership against the stored tuples
// for (object, relation) and writes/deletes the set difference in both
// directions. Keycloak is the source of truth; FGA state is derived from
// group membership on every pass. Idempotent.
func reconcileGroup(ctx context.Context, store Store, members GroupMemberLister, groupPath, object, relation string) error {
	ids, err := members.ListGroupMembers(ctx, groupPath)
	if err != nil {
		return err
	}
	desired := map[string]bool{}
	for _, id := range ids {
		desired[UserObject(id)] = true
	}
	existing, err := store.ReadTuples(ctx, object, relation)
	if err != nil {
		return err
	}
	actual := map[string]bool{}
	for _, t := range existing {
		actual[t.User] = true
	}
	var writes, deletes []Tuple
	for user := range desired {
		if !actual[user] {
			writes = append(writes, Tuple{User: user, Relation: relation, Object: object})
		}
	}
	for user := range actual {
		if !desired[user] {
			deletes = append(deletes, Tuple{User: user, Relation: relation, Object: object})
		}
	}
	if len(writes) > 0 {
		if err := store.WriteTuples(ctx, writes); err != nil {
			return err
		}
	}
	if len(deletes) > 0 {
		if err := store.DeleteTuples(ctx, deletes); err != nil {
			return err
		}
	}
	return nil
}

// Run reconciles on a ticker until ctx is cancelled; errors are logged, not fatal.
// A non-positive interval (misconfiguration) falls back to 30s instead of
// panicking in time.NewTicker.
func (s *PlatformGroupSync) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if err := s.SyncOnce(ctx); err != nil {
		slog.Warn("platform group sync", "error", err)
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := s.SyncOnce(ctx); err != nil {
				slog.Warn("platform group sync", "error", err)
			}
		}
	}
}
