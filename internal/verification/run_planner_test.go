package verification_test

import (
	"encoding/json"
	"testing"
	"time"

	contract "github.com/7K-Inari/inari-api/contract/verification/v1"
	"github.com/7K-Inari/inari-server/internal/types"
	verification "github.com/7K-Inari/inari-server/internal/verification"
)

func syncedInstance() *types.ResourceInstance {
	return &types.ResourceInstance{
		ID: "inst-1", UID: "2b6e4424-87a4-4f7c-b6d8-dfe2f6a894f8", OrgID: "org-1", ClusterID: "cluster-1",
		CatalogItemID: "hiroba/example", Version: "1.4.0", ArtifactDigest: digestA,
		Spec: json.RawMessage(`{"replicas":2}`), Generation: 4,
		CommitSHA: "0123456789abcdef0123456789abcdef01234567", ObservedRevision: "0123456789abcdef0123456789abcdef01234567",
		SyncState: "synced", SyncOperationID: "op-7", SyncOperationPhase: "Succeeded",
	}
}

func validRunPolicy(t *testing.T, instance *types.ResourceInstance) *verification.VerificationPolicy {
	t.Helper()
	specDigest, err := contract.DigestJSON(instance.Spec)
	if err != nil {
		t.Fatal(err)
	}
	p := validPolicy()
	p.Binding.SpecDigest = specDigest
	p.Binding.DesiredCommit = instance.CommitSHA
	p.InstanceUID = instance.UID
	return p
}

func TestBuildRunUsesSharedIdentityAndObservedRevision(t *testing.T) {
	instance := syncedInstance()
	policy := validRunPolicy(t, instance)
	now := time.Date(2026, 11, 21, 1, 2, 3, 0, time.UTC)
	trigger := policy.Trigger(contract.TriggerOnRevisionChange, "")
	run, err := verification.BuildRun(policy, 3, instance, trigger, now)
	if err != nil {
		t.Fatalf("BuildRun: %v", err)
	}
	if run == nil || run.ID == "" || run.RunKey == "" || run.TriggerFingerprint == "" || run.AppRevision == "" {
		t.Fatalf("incomplete run: %#v", run)
	}
	if run.Status != "verification_pending" || run.Disposition != "admission_pending" || run.LatestAttempt != 1 || run.GrantRevision != 3 {
		t.Fatalf("unexpected run state: %#v", run)
	}
	identity, err := contract.ComputeRunIdentity(instance.UID, run.AppRevision, run.SuiteDigest, trigger)
	if err != nil {
		t.Fatal(err)
	}
	if run.ID != identity.RunID || run.RunKey != identity.RunKey {
		t.Fatalf("identity mismatch: %#v vs %#v", run, identity)
	}
}

func TestBuildRunFailsClosedForStaleSync(t *testing.T) {
	instance := syncedInstance()
	policy := validRunPolicy(t, instance)
	trigger := policy.Trigger(contract.TriggerOnSync, "old-operation")
	if _, err := verification.BuildRun(policy, 1, instance, trigger, time.Now()); err == nil {
		t.Fatal("stale sync operation was accepted")
	}
	instance.ObservedRevision = ""
	if _, err := verification.BuildRun(policy, 1, instance, policy.Trigger(contract.TriggerOnRevisionChange, ""), time.Now()); err != nil {
		t.Fatalf("revision-change run should be plannable in waiting_for_sync: %v", err)
	} else if run, _ := verification.BuildRun(policy, 1, instance, policy.Trigger(contract.TriggerOnRevisionChange, ""), time.Now()); run.Disposition != "waiting_for_sync" {
		t.Fatalf("disposition = %q", run.Disposition)
	}
}

func TestBuildRunRequiresCurrentSyncForManualAndCron(t *testing.T) {
	instance := syncedInstance()
	instance.ObservedRevision = ""
	policy := validRunPolicy(t, instance)
	policy.Triggers.Cron.ScheduleSetID = "nightly"
	for _, trigger := range []contract.Trigger{
		policy.Trigger(contract.TriggerManual, "req-1"),
		policy.Trigger(contract.TriggerCron, "2026-11-21T02:00:00Z"),
	} {
		if _, err := verification.BuildRun(policy, 1, instance, trigger, time.Now()); err == nil {
			t.Fatalf("unsynced %s run was plannable", trigger.Kind)
		}
	}
}

func TestRevisionAndSyncTriggersIgnoreUnrelatedUpdates(t *testing.T) {
	previous := syncedInstance()
	current := *previous
	current.Health = "healthy"
	current.StatusMessage = "health changed"
	if verification.RevisionChanged(previous, &current) {
		t.Fatal("health-only update was treated as a revision change")
	}
	current.Generation++
	if !verification.RevisionChanged(previous, &current) {
		t.Fatal("generation change was not detected")
	}
	policy := validRunPolicy(t, previous)
	policy.Triggers.OnSync.Enabled = true
	previous.SyncOperationID = "op-6"
	current = *previous
	current.Health = "healthy"
	if verification.ShouldTriggerOnSync(policy, previous, &current) {
		t.Fatal("health-only event triggered onSync")
	}
	current.SyncOperationID = "op-7"
	current.SyncOperationPhase = "Succeeded"
	current.SyncState = "synced"
	if !verification.ShouldTriggerOnSync(policy, previous, &current) {
		t.Fatal("new successful operation did not trigger onSync")
	}
	if verification.ShouldTriggerOnSync(policy, &current, &current) {
		t.Fatal("duplicate operation triggered twice")
	}
}
