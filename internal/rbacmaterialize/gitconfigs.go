package rbacmaterialize

import (
	"context"

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
