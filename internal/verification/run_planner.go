package verification

import (
	"bytes"
	"errors"
	"time"

	contract "github.com/7K-Inari/inari-api/contract/verification/v1"
	"github.com/7K-Inari/inari-server/internal/types"
)

// BuildRun derives a durable run without performing admission or rendering.
func BuildRun(policy *VerificationPolicy, grantRevision int64, instance *types.ResourceInstance, trigger contract.Trigger, now time.Time) (*Run, error) {
	if policy == nil || instance == nil {
		return nil, errors.New("policy and instance are required")
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if grantRevision < 1 {
		return nil, errors.New("grantRevision must be positive")
	}
	if policy.InstanceID != instance.ID || policy.InstanceUID != instance.UID || policy.OrgID != instance.OrgID {
		return nil, errors.New("verification_binding_missing: policy instance identity mismatch")
	}
	b := policy.Binding
	if b.AppItemID != instance.CatalogItemID || b.AppVersion != instance.Version || b.AppArtifactDigest != instance.ArtifactDigest || b.DesiredCommit != instance.CommitSHA {
		return nil, errors.New("verification_stale: policy app binding does not match the current instance")
	}
	specDigest, err := contract.DigestJSON(instance.Spec)
	if err != nil {
		return nil, err
	}
	if specDigest != b.SpecDigest {
		return nil, errors.New("verification_stale: policy specDigest does not match the current instance")
	}
	appRevision, err := contract.ComputeAppRevision(contract.AppRevisionInput{
		InstanceUID: instance.UID, ItemID: instance.CatalogItemID, Version: instance.Version,
		ArtifactDigest: instance.ArtifactDigest, SpecDigest: specDigest,
		Generation: instance.Generation, DesiredCommit: instance.CommitSHA,
	})
	if err != nil {
		return nil, err
	}
	identity, err := contract.ComputeRunIdentity(instance.UID, appRevision, b.SuiteDigest, trigger)
	if err != nil {
		return nil, err
	}
	disposition := "waiting_for_sync"
	synced := instance.SyncState == "synced" && instance.ObservedRevision != "" && instance.CommitSHA != "" && instance.ObservedRevision == instance.CommitSHA
	if trigger.Kind == contract.TriggerOnSync {
		if !synced || instance.SyncOperationPhase != "Succeeded" || instance.SyncOperationID == "" || instance.SyncOperationID != trigger.OperationID {
			return nil, errors.New("app_revision_not_synced: sync operation does not match the current deployed revision")
		}
	}
	if synced {
		disposition = "admission_pending"
	}
	return &Run{
		ID: identity.RunID, RunKey: identity.RunKey, OrgID: instance.OrgID,
		InstanceID: instance.ID, InstanceUID: instance.UID, AppRevision: appRevision,
		AppArtifactDigest: instance.ArtifactDigest, SuiteDigest: b.SuiteDigest, Profile: b.Profile,
		Trigger: trigger, TriggerFingerprint: identity.TriggerFingerprint,
		Status: "verification_pending", Disposition: disposition,
		PolicyRevision: policy.Revision, GrantRevision: grantRevision, LatestAttempt: 1,
		CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}, nil
}

// RevisionChanged ignores health/sync observations and reports desired-state
// changes only.
func RevisionChanged(previous, current *types.ResourceInstance) bool {
	if previous == nil || current == nil {
		return previous != current
	}
	if previous.CatalogItemID != current.CatalogItemID || previous.Version != current.Version ||
		previous.ArtifactDigest != current.ArtifactDigest || previous.Generation != current.Generation ||
		previous.CommitSHA != current.CommitSHA {
		return true
	}
	previousDigest, previousErr := contract.DigestJSON(previous.Spec)
	currentDigest, currentErr := contract.DigestJSON(current.Spec)
	if previousErr != nil || currentErr != nil {
		return !bytes.Equal(previous.Spec, current.Spec)
	}
	return previousDigest != currentDigest
}

// ShouldTriggerOnSync accepts only a new successful operation for the exact
// current desired revision.
func ShouldTriggerOnSync(policy *VerificationPolicy, previous, current *types.ResourceInstance) bool {
	if policy == nil || !policy.Enabled || !policy.Triggers.OnSync.Enabled || previous == nil || current == nil {
		return false
	}
	if current.SyncOperationID == "" || current.SyncOperationPhase != "Succeeded" || current.SyncState != "synced" ||
		current.CommitSHA == "" || current.ObservedRevision != current.CommitSHA {
		return false
	}
	return previous.SyncOperationID != current.SyncOperationID || previous.SyncOperationPhase != "Succeeded" || previous.ObservedRevision != current.ObservedRevision
}
