package clusterdex

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/7K-Inari/inari-server/internal/featureflags"
	"github.com/7K-Inari/inari-server/internal/gitwebhook"
	"github.com/7K-Inari/inari-server/internal/types"
)

// OrgRenderer is the service seam the reconciler drives (testing seam).
type OrgRenderer interface {
	RerenderOrg(ctx context.Context, orgID string, staleClusterNames ...string) error
}

// FlagEvaluator is the feature-flag read seam (featureflags.Resolver).
type FlagEvaluator interface {
	Bool(ctx context.Context, key, clusterID string) bool
}

// Reconciler is the outbox consumer driving the Dex fan-out (decision D5):
// cluster.registered covers registration and label changes (labels only
// mutate via re-registration) and baseline rebinds; cluster.deleted drains;
// team/rbac events re-derive the ArgoCD group mapping; git.webhook.pr_merged
// closes the deferred-delivery loop on pull_request-policy repos. Re-render
// + commit happen only on drift, so the handler is quiet on unrelated
// events.
type Reconciler struct {
	svc   OrgRenderer
	flags FlagEvaluator
	log   *slog.Logger
}

// NewReconciler wires the consumer. flags may be nil (feature on).
func NewReconciler(svc OrgRenderer, flags FlagEvaluator, log *slog.Logger) *Reconciler {
	if log == nil {
		log = slog.Default()
	}
	return &Reconciler{svc: svc, flags: flags, log: log}
}

// EventTypes implements audit.Handler.
func (h *Reconciler) EventTypes() []string {
	return []string{
		types.EventClusterRegistered,
		types.EventClusterDeleted,
		types.EventTeamCreated,
		types.EventTeamDeleted,
		types.EventRBACMappingsUpdated,
		types.EventTenantCreated,
		string(gitwebhook.EventTypePRMerged),
	}
}

// Handle implements audit.Handler.
func (h *Reconciler) Handle(ctx context.Context, ev *types.OutboxEvent) error {
	if h.flags != nil && !h.flags.Bool(ctx, featureflags.KeyClusterDexFanout, "") {
		return nil
	}
	orgID := ev.OrgID
	var stale []string
	if ev.EventType == types.EventClusterDeleted {
		var p types.ClusterPayload
		if err := json.Unmarshal(ev.Payload, &p); err == nil {
			if p.OrgID != "" {
				orgID = p.OrgID
			}
			if p.Name != "" {
				stale = []string{p.Name}
			}
		}
	}
	if orgID == "" {
		var p struct {
			OrgID string `json:"orgId"`
		}
		if err := json.Unmarshal(ev.Payload, &p); err == nil {
			orgID = p.OrgID
		}
	}
	if orgID == "" {
		return nil
	}
	return h.svc.RerenderOrg(ctx, orgID, stale...)
}
