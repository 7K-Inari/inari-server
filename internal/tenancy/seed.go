package tenancy

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/types"
)

// PlatformOrgSlug is the reserved slug of the platform pseudo-org (ADR-0005,
// design decision D1): the 7kgroup platform cluster registers under it like
// any other org-scoped cluster. Precedent: the catalog module scopes its
// platform audit rows to OrgID "platform".
const PlatformOrgSlug = "platform"

// platformOrgDisplayName is the display name used when seeding.
const platformOrgDisplayName = "Inari Platform"

// seedActor is recorded on audit rows written by the seed (no human actor).
const seedActor = "system:seed"

// SeedPlatformOrg idempotently creates the reserved platform org: the
// Keycloak Organization, the DB projection, and the default teams (needed so
// ADR-0004 group→tuple sync and route-level FGA checks work for ops users
// who join the platform org). Unlike CreateTenant there is no creator
// membership — seeding is actor-free. It runs at control-plane startup
// (mirrors catalog.SeedPlatformApps) so the platform cluster can be
// registered through the standard cluster registry flow.
func (s *Service) SeedPlatformOrg(ctx context.Context) error {
	// Idempotent fast path: the org already exists.
	if _, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, PlatformOrgSlug); err == nil {
		return nil
	} else if !errors.Is(err, ErrOrgNotFound) {
		return err
	}

	kcOrgID, err := s.idp.CreateOrganization(ctx, PlatformOrgSlug, platformOrgDisplayName)
	if err != nil {
		return fmt.Errorf("tenancy: create platform keycloak organization: %w", err)
	}
	org := &types.Organization{
		ID:            "org:" + kcOrgID,
		Slug:          PlatformOrgSlug,
		DisplayName:   platformOrgDisplayName,
		KeycloakOrgID: kcOrgID,
	}
	var teams []types.Team
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.CreateOrganization(ctx, tx, org); err != nil {
			return err
		}
		seeds := make([]types.TeamSeed, 0, len(DefaultTeams))
		for _, dt := range DefaultTeams {
			team := types.Team{
				OrgID:             org.ID,
				Name:              dt.Name,
				Role:              dt.Role,
				KeycloakGroupPath: GroupPath(PlatformOrgSlug, dt.Name),
			}
			if err := s.store.CreateTeam(ctx, tx, &team); err != nil {
				return err
			}
			teams = append(teams, team)
			seeds = append(seeds, types.TeamSeed{TeamID: team.ID, Name: team.Name, Role: dt.Role})
			if err := s.audit.Record(ctx, tx, &types.AuditEvent{
				OrgID: org.ID, Actor: seedActor, Action: "team.created", ObjectType: "team", ObjectID: team.ID,
			}); err != nil {
				return err
			}
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: org.ID, Actor: seedActor, Action: "tenant.created", ObjectType: "organization", ObjectID: org.ID,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, org.ID, types.EventTenantCreated, types.TenantCreatedPayload{
			OrgID: org.ID, Slug: PlatformOrgSlug, Teams: seeds,
		})
	})
	if err != nil {
		if errors.Is(err, ErrSlugTaken) {
			// Concurrent seed (e.g. multi-replica startup): the other writer
			// won; the org now exists, so the seed goal is met.
			return nil
		}
		// Best-effort compensation for the external Keycloak write.
		if rbErr := s.idp.DeleteOrganization(ctx, kcOrgID); rbErr != nil {
			return fmt.Errorf("tenancy: %w (rollback keycloak org: %v)", err, rbErr)
		}
		return err
	}
	// Keycloak groups are created after the TX commits; group creation is
	// idempotent by path, same as CreateTenant.
	for _, tm := range teams {
		if _, err := s.idp.CreateGroup(ctx, tm.KeycloakGroupPath); err != nil {
			return fmt.Errorf("tenancy: create group %s: %w", tm.KeycloakGroupPath, err)
		}
	}
	return nil
}
