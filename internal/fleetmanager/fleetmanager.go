// Package fleetmanager implements the Fleet Manager module (plan §5.11):
// ClusterSets (label-selector cluster grouping, the targeting unit for fleet
// operations), staged health/approval-gated rollouts with stop/resume and
// rollback, agent upgrade channels, drift detection (report-only v1), and
// bulk operations. Execution stays credential-free: desired state is handed
// to agents through the durable command queue only.
package fleetmanager

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// ErrNotFound is returned for unknown cluster sets / rollouts / channels.
var ErrNotFound = errors.New("fleetmanager: not found")

// ErrInvalidInput is returned for malformed requests.
var ErrInvalidInput = errors.New("fleetmanager: invalid input")

// ErrInvalidTransition is returned for rollout state transitions that are
// not allowed from the current state.
var ErrInvalidTransition = errors.New("fleetmanager: invalid rollout transition")

// ClusterLister resolves an org's clusters (clusterregistry.Service seam).
type ClusterLister interface {
	ListClusters(ctx context.Context, orgID string) ([]types.Cluster, error)
}

// Queue enqueues desired-state commands for agents (agentgateway.Queue).
type Queue interface {
	Enqueue(ctx context.Context, cmd *types.AgentCommand) error
}

// Service is the fleet manager facade.
type Service struct {
	db       *db.DB
	store    *Store
	audit    *audit.Store
	clusters ClusterLister
	queue    Queue
	gates    GateRequester
	decider  ApprovalDecider
	assigner PolicyAssigner
	pinner   CatalogPinner
	now      func() time.Time
}

func NewService(d *db.DB, store *Store, auditStore *audit.Store, clusters ClusterLister, queue Queue) *Service {
	return &Service{db: d, store: store, audit: auditStore, clusters: clusters, queue: queue, now: time.Now}
}

// WithGateRequester wires the Approvals module seam for stage gates.
func (s *Service) WithGateRequester(g GateRequester) *Service { s.gates = g; return s }

func newUUID() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}
