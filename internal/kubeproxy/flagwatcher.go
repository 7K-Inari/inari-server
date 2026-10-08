package kubeproxy

import (
	"context"
	"log/slog"
	"time"
)

// DefaultFlagWatchInterval is how often FlagWatcher re-evaluates the
// kubectl_access.enabled flag for the platform and for every cluster with a
// live tunnel session.
const DefaultFlagWatchInterval = 2 * time.Second

// FlagWatcher applies runtime flag flips to live tunnel sessions: when
// kubectl_access.enabled turns off for the platform it closes all sessions;
// when it turns off for one cluster it closes just that cluster's session
// (cluster-scoped reversible disable, kill-switch v2). New tunnel connects
// are already rejected in TunnelHandler.Connect; this covers sessions that
// were live before the flip. Re-enable needs no hub action — the tunnel
// agent's supervised backoff loop reconnects on its own.
type FlagWatcher struct {
	Flags    FlagEvaluator
	Sessions *SessionRegistry
	Interval time.Duration

	platformDisabled bool
}

// NewFlagWatcher builds a watcher with the default poll interval.
func NewFlagWatcher(flags FlagEvaluator, sessions *SessionRegistry) *FlagWatcher {
	return &FlagWatcher{Flags: flags, Sessions: sessions, Interval: DefaultFlagWatchInterval}
}

// Run polls until ctx is cancelled.
func (w *FlagWatcher) Run(ctx context.Context) {
	if w.Interval <= 0 {
		w.Interval = DefaultFlagWatchInterval
	}
	t := time.NewTicker(w.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.tick(ctx)
		}
	}
}

func (w *FlagWatcher) tick(ctx context.Context) {
	if !w.Flags.KubectlAccessEnabled(ctx, "") {
		if !w.platformDisabled {
			slog.Warn("kubeproxy: kubectl access disabled platform-wide, closing all tunnel sessions")
			w.platformDisabled = true
		}
		w.Sessions.CloseAll("kubectl access is disabled by platform policy")
		return
	}
	w.platformDisabled = false
	for _, clusterID := range w.Sessions.Clusters() {
		if !w.Flags.KubectlAccessEnabled(ctx, clusterID) {
			slog.Warn("kubeproxy: kubectl access disabled for cluster, closing tunnel session", "cluster", clusterID)
			w.Sessions.CloseCluster(clusterID, "kubectl access is disabled by platform policy")
		}
	}
}
