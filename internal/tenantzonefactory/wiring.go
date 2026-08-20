// Production Inari-wiring implementation (plan §5.12 step 5): composes the
// tenancy, cluster registry, cloud accounts, and git provider modules to
// stand the new zone up end-to-end. Cross-module access goes through
// narrow seams so the composition stays testable.
package tenantzonefactory

import (
	"context"
	"errors"
	"fmt"

	"github.com/7K-Inari/inari-server/internal/cloudaccounts"
	"github.com/7K-Inari/inari-server/internal/clusterregistry"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

// TenantCreator provisions the Keycloak Organization + default teams
// (tenancy.Service seam).
type TenantCreator interface {
	CreateTenant(ctx context.Context, actor, slug, displayName string) (*types.Organization, []types.Team, error)
	GetTenant(ctx context.Context, slug string) (*types.Organization, error)
}

// OrgDeleter removes the Keycloak Organization on zone teardown
// (tenancy.IdentityProvider seam).
type OrgDeleter interface {
	DeleteOrganization(ctx context.Context, kcOrgID string) error
}

// ClusterRegistrar creates the Cluster record and issues the one-time
// registration token (clusterregistry.Service seam).
type ClusterRegistrar interface {
	CreateCluster(ctx context.Context, actor, orgID, name string, labels map[string]string) (*types.Cluster, error)
	ListClusters(ctx context.Context, orgID string) ([]types.Cluster, error)
	IssueToken(ctx context.Context, actor, clusterID string) (string, *types.RegistrationToken, error)
}

// AccountRegistrar creates/deregisters the zone's CloudAccount record
// (cloudaccounts.Service seam).
type AccountRegistrar interface {
	Register(ctx context.Context, actor, orgID string, in cloudaccounts.RegisterInput) (*types.CloudAccount, error)
	List(ctx context.Context, orgID string) ([]types.CloudAccount, error)
	Deregister(ctx context.Context, actor, orgID, id string) error
}

// GitConfigSetter points the tenant's state repo config at the zone repo
// (orchestrator.Service seam).
type GitConfigSetter interface {
	SetGitConfig(ctx context.Context, actor string, cfg *types.TenantGitConfig) error
}

// ModuleWiring is the production Wiring implementation.
type ModuleWiring struct {
	Tenants  TenantCreator
	IDP      OrgDeleter
	Clusters ClusterRegistrar
	Accounts AccountRegistrar
	Git      gitprovider.Provider
	GitCfg   GitConfigSetter
	Manifest clusterregistry.ManifestParams
}

// WireZone implements Wiring: Keycloak Organization → CloudAccount record
// (the trust-bootstrap OIDC role — same contract as BYO onboarding §5.7) →
// Cluster record + registration token → baseline bundle in the zone repo.
// Every sub-call is idempotent so the step can retry after failure.
func (w *ModuleWiring) WireZone(ctx context.Context, zone *types.TenantZone, roleARN string) (*WiringResult, error) {
	actor := "system:tenantzonefactory"
	org, _, err := w.Tenants.CreateTenant(ctx, actor, zone.Slug, zone.DisplayName)
	if errors.Is(err, tenancy.ErrSlugTaken) {
		// Retry after a partial run: adopt the existing organization.
		org, err = w.Tenants.GetTenant(ctx, zone.Slug)
	}
	if err != nil {
		return nil, fmt.Errorf("tzf: wiring keycloak org: %w", err)
	}
	acct, err := w.Accounts.Register(ctx, actor, org.ID, cloudaccounts.RegisterInput{
		AccountID: zone.AWSAccountID, RoleARN: roleARN, IssuerURL: "",
		RunContext: types.CloudAccountRunContextTenant,
	})
	if errors.Is(err, cloudaccounts.ErrAlreadyRegistered) {
		// Retry after a partial run: adopt the existing record.
		accts, lerr := w.Accounts.List(ctx, org.ID)
		if lerr != nil {
			return nil, fmt.Errorf("tzf: wiring cloud account lookup: %w", lerr)
		}
		for _, a := range accts {
			if a.AccountID == zone.AWSAccountID {
				acct = &a
				break
			}
		}
		if acct == nil {
			return nil, fmt.Errorf("tzf: wiring cloud account: registered record for %s not found", zone.AWSAccountID)
		}
	} else if err != nil {
		return nil, fmt.Errorf("tzf: wiring cloud account: %w", err)
	}
	clusterName := zone.Slug + "-eks"
	cluster, err := w.Clusters.CreateCluster(ctx, actor, org.ID, clusterName, map[string]string{
		"env": "zone", "region": zone.Region, "tier": zone.Tier, "zone": zone.Slug,
	})
	if errors.Is(err, clusterregistry.ErrClusterNameTaken) {
		// Retry after a partial run: adopt the existing record.
		clusters, lerr := w.Clusters.ListClusters(ctx, org.ID)
		if lerr != nil {
			return nil, fmt.Errorf("tzf: wiring cluster lookup: %w", lerr)
		}
		for _, c := range clusters {
			if c.Name == clusterName {
				cluster = &c
				break
			}
		}
		if cluster == nil {
			return nil, fmt.Errorf("tzf: wiring cluster record: %q not found after name-taken", clusterName)
		}
	} else if err != nil {
		return nil, fmt.Errorf("tzf: wiring cluster record: %w", err)
	}
	token, _, err := w.Clusters.IssueToken(ctx, actor, cluster.ID)
	if err != nil {
		return nil, fmt.Errorf("tzf: wiring registration token: %w", err)
	}
	repo := zone.Slug + "-inari-state"
	if err := w.Git.EnsureRepo(ctx, repo); err != nil {
		return nil, fmt.Errorf("tzf: wiring git repo: %w", err)
	}
	files, err := RenderBaseline(cluster, token, w.Manifest)
	if err != nil {
		return nil, err
	}
	if _, err := w.Git.CommitFiles(ctx, repo, "main", files, "feat: tenant-zone baseline (inari-agent, argocd, eso, policy packs)"); err != nil {
		return nil, fmt.Errorf("tzf: wiring baseline commit: %w", err)
	}
	if w.GitCfg != nil {
		if err := w.GitCfg.SetGitConfig(ctx, actor, &types.TenantGitConfig{
			OrgID: org.ID, Repo: repo, CommitPolicy: types.CommitPolicyDirect, BaseBranch: "main",
		}); err != nil {
			return nil, fmt.Errorf("tzf: wiring git config: %w", err)
		}
	}
	return &WiringResult{
		OrgID: org.ID, KeycloakOrgID: org.KeycloakOrgID,
		ClusterID: cluster.ID, CloudAccountID: acct.ID, GitRepo: repo,
	}, nil
}

// UnwireZone implements Wiring: revoke the zone's identities (Keycloak
// Organization removal; the cluster client was already disabled by the
// drain step's cluster decommission).
func (w *ModuleWiring) UnwireZone(ctx context.Context, zone *types.TenantZone) error {
	actor := "system:tenantzonefactory"
	if zone.CloudAccountID != "" && zone.OrgID != "" {
		if err := w.Accounts.Deregister(ctx, actor, zone.OrgID, zone.CloudAccountID); err != nil {
			return fmt.Errorf("tzf: unwire cloud account: %w", err)
		}
	}
	if zone.KeycloakOrgID != "" {
		if err := w.IDP.DeleteOrganization(ctx, zone.KeycloakOrgID); err != nil {
			return fmt.Errorf("tzf: unwire keycloak org: %w", err)
		}
	}
	return nil
}
