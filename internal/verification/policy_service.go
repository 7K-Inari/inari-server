package verification

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	contract "github.com/7K-Inari/inari-api/contract/verification/v1"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/resourcetargets"
	serverTypes "github.com/7K-Inari/inari-server/internal/types"
	"github.com/Masterminds/semver/v3"
	"github.com/jackc/pgx/v5"
)

var (
	ErrExternalGateClosed = errors.New("external_gate_closed: sibling 8f8c472a Phase 3 is unconfirmed")
	ErrConcurrency        = errors.New("verification: active run limit reached")
)

// PolicyPreview contains normalized policy and read-only effective guardrails.
type PolicyPreview struct {
	VerificationPolicy   *VerificationPolicy `json:"policy"`
	Environment          *EnvironmentPolicy  `json:"environment"`
	Grant                *SuiteGrant         `json:"grant"`
	Suite                *SuiteRelease       `json:"suite"`
	Gate                 GateStatus          `json:"gate"`
	WouldCreate          []string            `json:"wouldCreate,omitempty"`
	Warnings             []string            `json:"warnings,omitempty"`
	SideEffectsPerformed int                 `json:"sideEffectsPerformed"`
}

// VerificationView is the current policy/status projection.
type VerificationView struct {
	VerificationPolicy *VerificationPolicy `json:"policy,omitempty"`
	Gate               GateStatus          `json:"gate"`
	Runs               []Run               `json:"runs,omitempty"`
}

func (s *Service) CreateSuiteRelease(ctx context.Context, actor string, input SuiteAdmissionInput) (*SuiteRelease, error) {
	if s.db == nil {
		return nil, errors.New("verification database is not configured")
	}
	preview, err := s.PreviewSuite(ctx, input)
	if err != nil {
		return nil, err
	}
	release := preview.Release
	var inserted bool
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		var err error
		inserted, err = s.store.CreateSuiteRelease(ctx, tx, release)
		if err != nil {
			return err
		}
		if !inserted {
			existing, err := s.store.GetSuiteRelease(ctx, tx, release.OrgID, release.SuiteDigest)
			if err != nil {
				return err
			}
			if existing.ContentDigest != release.ContentDigest || !reflect.DeepEqual(existing.Descriptor, release.Descriptor) {
				return ErrConflict
			}
			release = existing
			return nil
		}
		return s.record(ctx, tx, release.OrgID, actor, "verification.suite_admitted", "verification_suite", release.ID, map[string]any{
			"orgId": release.OrgID, "suiteDigest": release.SuiteDigest, "contentDigest": release.ContentDigest,
			"sourceId": release.SourceID, "legacyException": release.LegacyException,
		})
	})
	return release, err
}

func (s *Service) PutEnvironmentPolicy(ctx context.Context, actor string, policy *EnvironmentPolicy) (*EnvironmentPolicy, error) {
	if s.db == nil || policy == nil {
		return nil, errors.New("environment policy and database are required")
	}
	normalizeEnvironmentPolicy(policy)
	revision, environment, err := s.store.TargetEnvironment(ctx, s.db.Pool, policy.OrgID, policy.TargetID)
	if err != nil {
		return nil, err
	}
	if environment == "" {
		environment = trustedsource.EnvironmentProduction
	}
	if policy.TargetRevision != revision || policy.Environment != environment {
		return nil, errors.New("target_stale: target revision or environment does not match the backing cluster")
	}
	current, err := s.store.GetEnvironmentPolicyByTarget(ctx, s.db.Pool, policy.OrgID, policy.TargetID)
	now := s.now().UTC()
	if errors.Is(err, ErrNotFound) {
		if policy.Revision != 1 {
			return nil, ErrConflict
		}
		policy.ID, err = newVerificationID("vep")
		if err != nil {
			return nil, err
		}
		policy.CreatedAt = now
	} else if err != nil {
		return nil, err
	} else {
		if policy.Revision != current.Revision+1 {
			return nil, ErrConflict
		}
		policy.ID, policy.CreatedAt = current.ID, current.CreatedAt
	}
	policy.UpdatedAt = now
	if err := validateEnvironmentPolicy(policy); err != nil {
		return nil, err
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.UpsertEnvironmentPolicy(ctx, tx, policy); err != nil {
			return err
		}
		return s.record(ctx, tx, policy.OrgID, actor, "verification.environment_updated", "verification_environment", policy.ID, map[string]any{
			"orgId": policy.OrgID, "targetId": policy.TargetID, "targetRevision": policy.TargetRevision,
			"policyRevision": policy.Revision, "environment": policy.Environment,
		})
	})
	return policy, err
}

func normalizeEnvironmentPolicy(policy *EnvironmentPolicy) {
	if policy.MaxTimeout == "" {
		policy.MaxTimeout = "15m"
	}
	if policy.MaxActive == 0 {
		policy.MaxActive = 1
	}
	if policy.MaxPending == 0 {
		policy.MaxPending = 1
	}
	if policy.MinWorkflowTTLSeconds == 0 {
		policy.MinWorkflowTTLSeconds = 60
	}
	if policy.MaxWorkflowTTLSeconds == 0 {
		policy.MaxWorkflowTTLSeconds = 3600
	}
	if policy.MaxResultDays == 0 {
		policy.MaxResultDays = 30
	}
	if policy.MaxEvidenceAgeAtApproval == "" {
		if policy.Environment == trustedsource.EnvironmentProduction {
			policy.MaxEvidenceAgeAtApproval = "24h"
		} else {
			policy.MaxEvidenceAgeAtApproval = "168h"
		}
	}
	if policy.MaxGrantLifetimeDays == 0 {
		if policy.Environment == trustedsource.EnvironmentProduction {
			policy.MaxGrantLifetimeDays = 30
		} else {
			policy.MaxGrantLifetimeDays = 90
		}
	}
	if len(policy.AllowedProfiles) == 0 {
		if policy.Environment == trustedsource.EnvironmentProduction {
			policy.AllowedProfiles = []string{ProfileProd}
		} else {
			policy.AllowedProfiles = []string{ProfileStage}
		}
	}
	if len(policy.AllowedTriggers) == 0 {
		policy.AllowedTriggers = []string{"onRevisionChange", "onSync", "manual", "cron"}
	}
	if len(policy.AllowedFailureActions) == 0 {
		policy.AllowedFailureActions = []string{FailureNotify, FailurePausePromotion, FailureBlockPromotion}
	}
}

func validateEnvironmentPolicy(policy *EnvironmentPolicy) error {
	if policy.OrgID == "" || policy.TargetID == "" || policy.Revision < 1 {
		return errors.New("orgId, targetId, and positive policyRevision are required")
	}
	if timeout, err := time.ParseDuration(policy.MaxTimeout); err != nil || timeout < time.Second || timeout > time.Hour {
		return errors.New("maxTimeout must be between 1s and 1h")
	}
	if policy.MaxActive < 1 || policy.MaxActive > 100 || policy.MaxPending < 0 || policy.MaxPending > 1000 {
		return errors.New("environment concurrency limits are invalid")
	}
	if policy.MinWorkflowTTLSeconds < 60 || policy.MaxWorkflowTTLSeconds < policy.MinWorkflowTTLSeconds || policy.MaxResultDays < 1 || policy.MaxResultDays > 365 {
		return errors.New("environment retention limits are invalid")
	}
	if age, err := time.ParseDuration(policy.MaxEvidenceAgeAtApproval); err != nil || age <= 0 || age > 30*24*time.Hour {
		return errors.New("maxEvidenceAgeAtApproval must be a positive duration up to 720h")
	}
	if policy.MaxGrantLifetimeDays < 1 || policy.MaxGrantLifetimeDays > 365 {
		return errors.New("maxGrantLifetimeDays must be between 1 and 365")
	}
	for _, profile := range policy.AllowedProfiles {
		if policy.Environment == trustedsource.EnvironmentProduction && profile != ProfileProd || policy.Environment != trustedsource.EnvironmentProduction && profile != ProfileStage {
			return errors.New("allowedProfiles contains an environment-incompatible profile")
		}
	}
	for _, trigger := range policy.AllowedTriggers {
		if trigger != "onRevisionChange" && trigger != "onSync" && trigger != "manual" && trigger != "cron" {
			return fmt.Errorf("unknown allowed trigger %q", trigger)
		}
	}
	for _, action := range policy.AllowedFailureActions {
		if action != FailureNotify && action != FailurePausePromotion && action != FailureBlockPromotion {
			return fmt.Errorf("unknown failure action %q", action)
		}
	}
	return nil
}

func (s *Service) PutGrant(ctx context.Context, actor string, grant *SuiteGrant) (*SuiteGrant, error) {
	if s.db == nil || grant == nil {
		return nil, errors.New("grant and database are required")
	}
	environment, err := s.store.GetEnvironmentPolicy(ctx, s.db.Pool, grant.OrgID, grant.EnvironmentPolicyID)
	if err != nil {
		return nil, err
	}
	grant.OrgID = environment.OrgID
	release, err := s.store.GetSuiteRelease(ctx, s.db.Pool, environment.OrgID, grant.SuiteDigest)
	if err != nil {
		return nil, err
	}
	if grant.SuiteReleaseID != "" && grant.SuiteReleaseID != release.ID {
		return nil, errors.New("suiteReleaseId does not match suiteDigest")
	}
	grant.SuiteReleaseID = release.ID
	if grant.ID != "" {
		current, err := s.store.GetGrant(ctx, s.db.Pool, grant.OrgID, grant.ID)
		if err != nil {
			return nil, err
		}
		if grant.Revision != current.Revision+1 || grant.EnvironmentPolicyID != current.EnvironmentPolicyID ||
			grant.SuiteDigest != current.SuiteDigest || grant.Profile != current.Profile {
			// Environment and digest+profile are immutable grant identity fields.
			return nil, ErrConflict
		}
	} else if grant.Revision != 1 {
		return nil, ErrConflict
	}
	if grant.Revision == 1 {
		grant.ID, err = newVerificationID("vsg")
		if err != nil {
			return nil, err
		}
	}
	preview, err := s.PreviewSuite(ctx, SuiteAdmissionInput{
		OrgID: grant.OrgID, SourceID: release.SourceID, Descriptor: release.Descriptor,
		Environment: environment.Environment, Profile: grant.Profile,
		LegacyNonProductionException: grant.LegacyNonProductionException,
	})
	if err != nil {
		return nil, err
	}
	if preview.Release.ContentDigest != release.ContentDigest {
		return nil, errors.New("suite source policy or content changed; import a fresh suite release")
	}
	if environment.Environment == trustedsource.EnvironmentProduction {
		maxAge, _ := time.ParseDuration(environment.MaxEvidenceAgeAtApproval)
		finished := preview.Release.EvidenceFinishedAt
		if finished.IsZero() || finished.After(s.now().Add(5*time.Minute)) || finished.Before(s.now().Add(-maxAge)) {
			return nil, errors.New("test_evidence_invalid: production grant requires fresh signed release evidence")
		}
	}
	if err := grant.ValidateGrant(environment); err != nil {
		return nil, err
	}
	if suiteProfile := preview.Release.Suite.Profiles[grant.Profile]; suiteProfile.SideEffects != grant.SideEffect {
		return nil, errors.New("grant sideEffects must match the signed suite profile")
	}
	if err := ValidateWorkflowTemplate(preview.Release.WorkflowTemplate, &preview.Release.Suite, grant); err != nil {
		return nil, err
	}
	if err := validateRBACSubset(preview.Release.Suite.RBACRequirements, grant.AllowedRBAC); err != nil {
		return nil, err
	}
	now := s.now().UTC()
	maxExpiry := now.Add(time.Duration(environment.MaxGrantLifetimeDays) * 24 * time.Hour)
	if grant.ExpiresAt == nil {
		expires := maxExpiry
		grant.ExpiresAt = &expires
	} else if grant.ExpiresAt.After(maxExpiry) || !grant.ExpiresAt.After(now) {
		return nil, errors.New("grant expiry exceeds the environment lifetime or is already expired")
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.UpsertGrant(ctx, tx, grant); err != nil {
			return err
		}
		return s.record(ctx, tx, grant.OrgID, actor, "verification.grant_updated", "verification_grant", grant.ID, map[string]any{
			"orgId": grant.OrgID, "suiteDigest": grant.SuiteDigest, "profile": grant.Profile,
			"grantRevision": grant.Revision, "legacyException": grant.LegacyNonProductionException,
			"serviceAccountNamespace": grant.ServiceAccountNamespace, "serviceAccountName": grant.ServiceAccountName,
		})
	})
	return grant, err
}

func validateRBACSubset(required, allowed []RBACRule) error {
	for _, requirement := range required {
		for _, group := range requirement.APIGroups {
			for _, resource := range requirement.Resources {
				for _, verb := range requirement.Verbs {
					matched := false
					for _, rule := range allowed {
						if contains(rule.APIGroups, group) && contains(rule.Resources, resource) && contains(rule.Verbs, verb) {
							matched = true
							break
						}
					}
					if !matched {
						return fmt.Errorf("rbac_requirement_denied: %s %s %s is not preapproved", group, resource, verb)
					}
				}
			}
		}
	}
	return nil
}

func (s *Service) PreviewPolicy(ctx context.Context, orgID, subject string, policy *VerificationPolicy) (*PolicyPreview, error) {
	if s.db == nil || s.instances == nil || s.targets == nil || s.suites == nil {
		return nil, errors.New("verification preview dependencies are not configured")
	}
	if policy == nil || policy.InstanceID == "" {
		return nil, errors.New("policy and instanceId are required")
	}
	instance, err := s.instances.Get(ctx, s.db.Pool, policy.InstanceID)
	if err != nil {
		return nil, err
	}
	if instance.OrgID != orgID {
		return nil, ErrNotFound
	}
	// Instance identity is server-bound; clients cannot claim another UID/org.
	policy.OrgID, policy.InstanceUID = orgID, instance.UID
	if policy.Binding.SpecDigest == "" {
		// Derive from the server's exact stored JSON instead of asking a browser
		// to reproduce Go's number-preserving canonicalization. This also lets a
		// team intentionally rebind after a spec-only change.
		digest, err := contract.DigestJSON(instance.Spec)
		if err != nil {
			return nil, err
		}
		policy.Binding.SpecDigest = digest
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	grant, err := s.store.GetGrant(ctx, s.db.Pool, orgID, policy.Binding.SuiteGrantID)
	if err != nil {
		return nil, err
	}
	environment, err := s.store.GetEnvironmentPolicy(ctx, s.db.Pool, orgID, grant.EnvironmentPolicyID)
	if err != nil {
		return nil, err
	}
	resolved, err := s.targets.ResolveResource(ctx, orgID, subject, resourcetargets.CapabilityDeploymentCluster, resourcetargets.ActionUse,
		resourcetargets.TargetResourceRef{Kind: resourcetargets.ResourceKindCluster, ID: instance.ClusterID}, nil)
	if err != nil {
		return nil, err
	}
	if resolved == nil || resolved.Target.ID != environment.TargetID || resolved.Target.Revision != environment.TargetRevision || resolved.Cluster == nil {
		return nil, errors.New("target_stale: verification environment target mismatch")
	}
	if env := resolved.Cluster.Labels["inari.dev/environment"]; env != "" && trustedsource.Environment(env) != environment.Environment {
		return nil, errors.New("target_stale: cluster environment changed")
	}
	if err := policy.ValidateAgainstGrant(environment, grant, s.now()); err != nil {
		return nil, err
	}
	for _, enabled := range []struct {
		kind    string
		enabled bool
	}{{"onRevisionChange", policy.Triggers.OnRevisionChange.Enabled}, {"onSync", policy.Triggers.OnSync.Enabled},
		{"manual", policy.Triggers.Manual.Enabled}, {"cron", policy.Triggers.Cron.Enabled}} {
		if enabled.enabled && !contains(environment.AllowedTriggers, enabled.kind) {
			return nil, fmt.Errorf("trigger %s is denied by environment policy", enabled.kind)
		}
	}
	release, err := s.store.GetSuiteRelease(ctx, s.db.Pool, orgID, policy.Binding.SuiteDigest)
	if err != nil {
		return nil, err
	}
	if release.ID != grant.SuiteReleaseID || release.Suite.ParameterContract != policy.Binding.ParameterContract {
		return nil, errors.New("verification_binding_missing: suite release or parameter contract mismatch")
	}
	app, err := s.suites.AdmitVersion(ctx, instance.CatalogItemID, instance.Version, environment.Environment)
	if err != nil {
		return nil, err
	}
	if app == nil || app.Version == nil || app.Version.ArtifactDigest != instance.ArtifactDigest {
		return nil, errors.New("verification_stale: admitted app artifact mismatch")
	}
	var payload struct {
		Admission struct {
			Runtime *trustedsource.RuntimeEvidence `json:"runtime"`
		} `json:"admission"`
	}
	if err := json.Unmarshal(app.Version.Payload, &payload); err != nil || payload.Admission.Runtime == nil {
		return nil, errors.New("verification_binding_missing: signed app Runtime evidence is required")
	}
	runtimeEvidence := payload.Admission.Runtime
	if runtimeEvidence.Result != "passed" || runtimeEvidence.SuiteDigest != policy.Binding.SuiteDigest || runtimeEvidence.Target != release.Suite.Target.ID {
		return nil, errors.New("verification_binding_missing: exact app Runtime suite binding mismatch")
	}
	appVersion, err := semver.StrictNewVersion(instance.Version)
	if err != nil {
		return nil, err
	}
	constraint, err := semver.NewConstraint(release.Suite.CompatibleAppVersions)
	if err != nil || !constraint.Check(appVersion) {
		return nil, errors.New("app_version_incompatible: signed suite does not support this app version")
	}
	if grant.AppItemID != "" && grant.AppItemID != instance.CatalogItemID {
		return nil, errors.New("suite_grant_denied: app item is outside the grant")
	}
	if grant.AppVersionRange != "" {
		grantRange, err := semver.NewConstraint(grant.AppVersionRange)
		if err != nil || !grantRange.Check(appVersion) {
			return nil, errors.New("suite_grant_denied: app version is outside the grant")
		}
	}
	// Re-admit the exact suite for this environment and compare immutable content.
	suitePreview, err := s.PreviewSuite(ctx, SuiteAdmissionInput{
		OrgID: orgID, SourceID: release.SourceID, Descriptor: release.Descriptor,
		Environment: environment.Environment, Profile: policy.Binding.Profile,
		LegacyNonProductionException: grant.LegacyNonProductionException,
	})
	if err != nil {
		return nil, err
	}
	if suitePreview.Release.ContentDigest != release.ContentDigest {
		return nil, errors.New("verification_stale: suite content or source policy changed")
	}
	// Policy preview validates the exact desired binding. It is not a manual
	// execution request and may legitimately precede the first observed sync;
	// manual/cron preflight applies its stricter sync rule separately.
	if _, err := BuildRun(policy, grant.Revision, instance, policy.Trigger(contract.TriggerOnRevisionChange, ""), s.now()); err != nil {
		return nil, err
	}
	wouldCreate := []string{}
	if policy.Enabled {
		wouldCreate = append(wouldCreate, "WorkflowTemplate")
		if policy.Triggers.OnSync.Enabled && policy.Triggers.OnSync.Mode == "postSync" {
			wouldCreate = append(wouldCreate, "PostSync Workflow")
		} else if policy.Triggers.OnRevisionChange.Enabled || policy.Triggers.OnSync.Enabled || policy.Triggers.Manual.Enabled {
			wouldCreate = append(wouldCreate, "Workflow")
		}
		if policy.Triggers.Cron.Enabled {
			wouldCreate = append(wouldCreate, "CronWorkflow")
		}
	}
	preview := &PolicyPreview{
		VerificationPolicy: policy, Environment: environment, Grant: grant, Suite: suitePreview.Release,
		Gate: s.GateStatus(), WouldCreate: wouldCreate, SideEffectsPerformed: 0,
	}
	if grant.LegacyNonProductionException {
		preview.Warnings = append(preview.Warnings, "legacy_eligibility_exception: non-production/non-evidence only")
	}
	return preview, nil
}

func (s *Service) PutPolicy(ctx context.Context, orgID, subject string, policy *VerificationPolicy) (*VerificationPolicy, error) {
	preview, err := s.PreviewPolicy(ctx, orgID, subject, policy)
	if err != nil {
		return nil, err
	}
	current, err := s.store.GetCurrentPolicy(ctx, s.db.Pool, orgID, policy.InstanceID)
	now := s.now().UTC()
	if errors.Is(err, ErrNotFound) {
		if policy.Revision != 1 {
			return nil, ErrConflict
		}
	} else if err != nil {
		return nil, err
	} else if policy.Revision != current.Revision+1 {
		return nil, ErrConflict
	}
	policy.ID, err = newVerificationID("vp")
	if err != nil {
		return nil, err
	}
	policy.Current, policy.CreatedAt, policy.UpdatedAt = true, now, now
	fingerprintInput, _ := json.Marshal(map[string]any{
		"policy": policy, "suiteContentDigest": preview.Suite.ContentDigest,
		"grantRevision": preview.Grant.Revision, "environmentRevision": preview.Environment.Revision,
	})
	renderFingerprint, err := contract.DigestJSON(fingerprintInput)
	if err != nil {
		return nil, err
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.PutPolicy(ctx, tx, policy, renderFingerprint); err != nil {
			return err
		}
		return s.record(ctx, tx, orgID, subject, "verification.policy_updated", "verification_policy", policy.ID, map[string]any{
			"orgId": orgID, "instanceId": policy.InstanceID, "instanceUid": policy.InstanceUID,
			"policyRevision": policy.Revision, "appArtifactDigest": policy.Binding.AppArtifactDigest,
			"suiteDigest": policy.Binding.SuiteDigest, "profile": policy.Binding.Profile,
			"renderFingerprint": renderFingerprint, "externalGate": s.GateStatus().Reason,
		})
	})
	return policy, err
}

func (s *Service) GetVerification(ctx context.Context, orgID, instanceID string) (*VerificationView, error) {
	if s.db == nil {
		return nil, errors.New("verification database is not configured")
	}
	policy, err := s.store.GetCurrentPolicy(ctx, s.db.Pool, orgID, instanceID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if errors.Is(err, ErrNotFound) {
		policy = nil
	}
	runs, err := s.store.ListRuns(ctx, s.db.Pool, orgID, instanceID, 20)
	if err != nil {
		return nil, err
	}
	return &VerificationView{VerificationPolicy: policy, Gate: s.GateStatus(), Runs: runs}, nil
}

func (s *Service) PreviewManualRun(ctx context.Context, orgID, subject, instanceID, requestKey string) (*PolicyPreview, error) {
	if strings.TrimSpace(requestKey) == "" {
		return nil, errors.New("idempotencyKey is required")
	}
	policy, err := s.store.GetCurrentPolicy(ctx, s.db.Pool, orgID, instanceID)
	if err != nil {
		return nil, err
	}
	if !policy.Enabled || !policy.Triggers.Manual.Enabled {
		return nil, errors.New("manual trigger is disabled")
	}
	preview, err := s.PreviewPolicy(ctx, orgID, subject, policy)
	if err != nil {
		return nil, err
	}
	instance, err := s.instances.Get(ctx, s.db.Pool, instanceID)
	if err != nil {
		return nil, err
	}
	if _, err := BuildRun(policy, preview.Grant.Revision, instance, policy.Trigger(contract.TriggerManual, requestKey), s.now()); err != nil {
		return nil, err
	}
	return preview, nil
}

func (s *Service) CreateManualRun(ctx context.Context, orgID, subject, instanceID, requestKey string) (*Run, error) {
	if _, err := s.PreviewManualRun(ctx, orgID, subject, instanceID, requestKey); err != nil {
		return nil, err
	}
	// Deliberately no hidden gate override or stale queued run. The future
	// sibling renderer will resume implementation at this exact boundary.
	return nil, ErrExternalGateClosed
}

func (s *Service) record(ctx context.Context, q db.Querier, orgID, actor, action, objectType, objectID string, payload any) error {
	if s.audit == nil {
		return nil
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := s.audit.Record(ctx, q, &serverTypes.AuditEvent{
		OrgID: orgID, Actor: actor, Action: action, ObjectType: objectType, ObjectID: objectID, Payload: raw,
	}); err != nil {
		return err
	}
	return audit.AppendOutbox(ctx, q, orgID, action, payload)
}

func newVerificationID(prefix string) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + "-" + hex.EncodeToString(raw), nil
}
