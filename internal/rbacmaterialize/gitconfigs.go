package rbacmaterialize

import (
	"context"
	"errors"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/types"
)

// inventoryGitConfigs adapts inventory.Store to the GitConfigs seam: the
// tenant git-config projection lives in the inventory module's store.
type inventoryGitConfigs struct {
	db    *db.DB
	store *inventory.Store
}

// NewInventoryGitConfigs wires the production GitConfigs implementation.
func NewInventoryGitConfigs(database *db.DB, store *inventory.Store) GitConfigs {
	return &inventoryGitConfigs{db: database, store: store}
}

func (a *inventoryGitConfigs) GitConfig(ctx context.Context, orgID string) (*types.TenantGitConfig, error) {
	return a.store.GitConfig(ctx, a.db.Pool, orgID)
}

// inventoryGitRepos adapts inventory.Store to the GitRepos registry seam
// (Feature A): the default row targets the baseline write; team rows feed
// the opt-in per-team writes.
type inventoryGitRepos struct {
	db    *db.DB
	store *inventory.Store
}

// NewInventoryGitRepos wires the production GitRepos implementation.
func NewInventoryGitRepos(database *db.DB, store *inventory.Store) GitRepos {
	return &inventoryGitRepos{db: database, store: store}
}

func (a *inventoryGitRepos) GetDefaultGitRepo(ctx context.Context, orgID string) (*types.TenantGitRepo, error) {
	row, err := a.store.GetDefaultGitRepo(ctx, a.db.Pool, orgID)
	if errors.Is(err, inventory.ErrRepoNotFound) {
		return nil, nil
	}
	return row, err
}

func (a *inventoryGitRepos) ListTeamGitRepos(ctx context.Context, orgID string) ([]*types.TenantGitRepo, error) {
	// An empty teamIDs filter returns all repos; keep only team-scope rows
	// with an owning team.
	all, err := a.store.ListGitRepos(ctx, a.db.Pool, orgID, nil)
	if err != nil {
		return nil, err
	}
	out := make([]*types.TenantGitRepo, 0, len(all))
	for _, r := range all {
		if r.Scope == types.GitRepoScopeTeam && r.TeamID != "" {
			out = append(out, r)
		}
	}
	return out, nil
}
