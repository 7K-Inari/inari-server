// Agent upgrade channels (plan §5.11): the desired agent version is pinned
// per ClusterSet per channel (stable/canary). The control plane supports
// agent versions N and N−1; the skew is enforced at the agent gateway
// handshake and pinned by contract CI against inari-api (§11/5).
package fleetmanager

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/types"
)

// SetAgentChannel pins the desired agent version for a ClusterSet channel.
func (s *Service) SetAgentChannel(ctx context.Context, actor, orgID, clusterSetID, channel, version string) (*types.AgentChannel, error) {
	if channel != types.AgentChannelStable && channel != types.AgentChannelCanary {
		return nil, fmt.Errorf("%w: channel must be stable|canary", ErrInvalidInput)
	}
	if version == "" {
		return nil, fmt.Errorf("%w: version is required", ErrInvalidInput)
	}
	if _, err := s.GetClusterSet(ctx, orgID, clusterSetID); err != nil {
		return nil, err
	}
	c := &types.AgentChannel{
		ID: "agentchannel:" + newUUID(), OrgID: orgID, ClusterSetID: clusterSetID,
		Channel: channel, DesiredAgentVersion: version,
	}
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.upsertChannel(ctx, tx, c); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "agent_channel.set",
			ObjectType: "cluster_set", ObjectID: clusterSetID,
			Payload: []byte(fmt.Sprintf(`{"channel":%q,"version":%q}`, channel, version)),
		})
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

// ListAgentChannels returns the org's channel pins.
func (s *Service) ListAgentChannels(ctx context.Context, orgID string) ([]types.AgentChannel, error) {
	return s.store.listChannels(ctx, s.db.Pool, orgID)
}

// SupportedAgentVersion reports whether the control plane serves the given
// agent version: only N (current) and N−1 are supported (plan §11/5).
// Versions are semver-ish "vX.Y.Z"; skew is evaluated on the minor of the
// current major line.
func SupportedAgentVersion(current, reported string) bool {
	curMaj, curMin, ok := parseMajorMinor(current)
	if !ok {
		return false
	}
	repMaj, repMin, ok := parseMajorMinor(reported)
	if !ok {
		return false
	}
	if repMaj != curMaj {
		return false
	}
	return repMin == curMin || repMin == curMin-1
}

func parseMajorMinor(v string) (maj, min int, ok bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return 0, 0, false
	}
	maj, err1 := strconv.Atoi(parts[0])
	min, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return maj, min, true
}
