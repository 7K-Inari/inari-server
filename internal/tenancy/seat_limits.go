package tenancy

import (
	"context"

	"github.com/7K-Inari/inari-server/internal/planlimits"
	"github.com/7K-Inari/inari-server/internal/types"
)

// admitNewSeat serializes inline membership admission across server replicas
// and holds the lock until the caller finishes its Keycloak + projection work.
// Existing members never consume another seat when joining another team.
func (s *Service) admitNewSeat(ctx context.Context, org *types.Organization, userID string) (func(), error) {
	noop := func() {}
	evaluation, err := s.evaluateLimits(ctx, org.ID)
	if err != nil {
		return noop, err
	}
	if evaluation.MaxDeveloperSeats() == nil {
		return noop, nil
	}
	conn, err := s.db.Pool.Acquire(ctx)
	if err != nil {
		return noop, err
	}
	release := func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtext($1))`, "planlimits/seats/"+org.ID)
		conn.Release()
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtext($1))`, "planlimits/seats/"+org.ID); err != nil {
		conn.Release()
		return noop, err
	}
	members, err := s.idp.ListOrganizationMembers(ctx, org.KeycloakOrgID)
	if err != nil {
		release()
		return noop, err
	}
	distinct := make(map[string]struct{}, len(members)+1)
	for _, member := range members {
		distinct[member.ID] = struct{}{}
	}
	if _, existing := distinct[userID]; existing {
		return release, nil
	}
	if err := evaluation.CheckQuota(planlimits.LimitDeveloperSeats, int64(len(distinct))); err != nil {
		release()
		return noop, err
	}
	return release, nil
}
