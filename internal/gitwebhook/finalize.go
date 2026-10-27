package gitwebhook

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/7K-Inari/inari-server/internal/types"
)

// PRMergeCompleter closes the PR-merge gap for one workload kind
// (implemented by orchestrator.Service for instances and addons.Service
// for cluster addons): record the merge SHA and enqueue the ArgoCD
// registration that was deferred while the PR was open. found=false means
// no row awaited that PR URL.
type PRMergeCompleter interface {
	FinalizePRMerge(ctx context.Context, orgID, prURL, mergeSHA string) (found bool, err error)
}

// MergeFinalizer is the first normalized-event subscriber (audit.Handler):
// on git.webhook.pr_merged it completes the deferred registration of the
// matching instance or addon. Finalization is idempotent — a redelivered
// or late webhook matches nothing and is acked, and the agent status
// stream remains the fallback when a webhook is missed entirely.
type MergeFinalizer struct {
	instances PRMergeCompleter
	addons    PRMergeCompleter
	log       *slog.Logger
}

// NewMergeFinalizer wires the subscriber. Either completer may be nil
// (skipped). log may be nil.
func NewMergeFinalizer(instances, addons PRMergeCompleter, log *slog.Logger) *MergeFinalizer {
	if log == nil {
		log = slog.Default()
	}
	return &MergeFinalizer{instances: instances, addons: addons, log: log}
}

// EventTypes implements audit.Handler.
func (h *MergeFinalizer) EventTypes() []string { return []string{string(EventTypePRMerged)} }

// Handle implements audit.Handler.
func (h *MergeFinalizer) Handle(ctx context.Context, ev *types.OutboxEvent) error {
	var p PRMergedPayload
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		return fmt.Errorf("gitwebhook: parse %s payload: %w", EventTypePRMerged, err)
	}
	if p.PRURL == "" {
		// Nothing can match without the PR URL — ack.
		return nil
	}
	if h.instances != nil {
		found, err := h.instances.FinalizePRMerge(ctx, ev.OrgID, p.PRURL, p.MergeSHA)
		if err != nil {
			return err
		}
		if found {
			h.log.Info("gitwebhook: instance PR merge finalized", "org", ev.OrgID, "pr", p.PRURL, "mergeSha", p.MergeSHA)
			return nil
		}
	}
	if h.addons != nil {
		found, err := h.addons.FinalizePRMerge(ctx, ev.OrgID, p.PRURL, p.MergeSHA)
		if err != nil {
			return err
		}
		if found {
			h.log.Info("gitwebhook: addon PR merge finalized", "org", ev.OrgID, "pr", p.PRURL, "mergeSha", p.MergeSHA)
			return nil
		}
	}
	// No row awaited this PR (already finalized, or not ours) — ack.
	return nil
}
