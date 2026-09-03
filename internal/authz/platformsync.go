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

// SyncOnce diffs group membership against stored org_creator tuples and
// writes/deletes the difference. Idempotent.
func (s *PlatformGroupSync) SyncOnce(ctx context.Context) error {
	ids, err := s.members.ListGroupMembers(ctx, s.group)
	if err != nil {
		return err
	}
	desired := map[string]bool{}
	for _, id := range ids {
		desired[UserObject(id)] = true
	}
	existing, err := s.store.ReadTuples(ctx, ObjectPlatform, RelationOrgCreator)
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
			writes = append(writes, Tuple{User: user, Relation: RelationOrgCreator, Object: ObjectPlatform})
		}
	}
	for user := range actual {
		if !desired[user] {
			deletes = append(deletes, Tuple{User: user, Relation: RelationOrgCreator, Object: ObjectPlatform})
		}
	}
	if len(writes) > 0 {
		if err := s.store.WriteTuples(ctx, writes); err != nil {
			return err
		}
	}
	if len(deletes) > 0 {
		if err := s.store.DeleteTuples(ctx, deletes); err != nil {
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
