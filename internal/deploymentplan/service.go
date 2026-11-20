package deploymentplan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	observability "github.com/7K-Inari/inari-api/contract/observability/v1"
	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/oci"
	"github.com/7K-Inari/inari-server/internal/resourcetargets"
	"github.com/7K-Inari/inari-server/internal/types"
	"github.com/google/uuid"
)

var ErrNotImplemented = errors.New("deployment plan not implemented")

type Catalog interface {
	GetItemByID(ctx context.Context, itemID string) (*types.CatalogItem, error)
	EffectiveVersion(ctx context.Context, orgID, itemID, channel string) (string, error)
	GetVersion(ctx context.Context, itemID, version string) (*types.CatalogItemVersion, error)
	ListVersions(ctx context.Context, itemID string) ([]types.CatalogItemVersion, error)
	ListVisible(ctx context.Context, orgID string, opts types.CatalogListOptions) ([]catalog.ItemView, int, error)
	EnsureVisible(ctx context.Context, orgID, clusterID, itemID string) error
	AdmitVersion(ctx context.Context, itemID, version string, environment trustedsource.Environment) (*catalog.AdmittedVersion, error)
}

type Targets interface {
	List(ctx context.Context, orgID, subject string, filter resourcetargets.ListFilter) ([]resourcetargets.Target, error)
	Get(ctx context.Context, orgID, subject, targetID string) (*resourcetargets.Target, error)
	Resolve(ctx context.Context, in resourcetargets.ResolveInput) (*resourcetargets.ResolvedTarget, error)
	Providers() []resourcetargets.ProviderDescriptor
}

type ChartFetcher interface {
	Fetch(ctx context.Context, ref string) (*oci.Artifact, error)
}

type AppExecutor interface {
	Execute(ctx context.Context, orgID, subject string, plan *Plan) (instanceID, scaffoldRunID string, err error)
}

type Service struct {
	db       *db.DB
	store    Store
	catalog  Catalog
	targets  Targets
	charts   ChartFetcher
	executor AppExecutor
	gate     GateStatus
	now      func() time.Time
	newID    func() string
}

func NewService(d *db.DB, store Store) *Service {
	return &Service{db: d, store: store, now: time.Now, newID: func() string { return uuid.NewString() }, gate: GateStatus{Reason: "sibling_8f8c472a_phase_3_unconfirmed"}}
}

func (s *Service) WithDependencies(cat Catalog, targets Targets, charts ChartFetcher, executor AppExecutor) *Service {
	s.catalog, s.targets, s.charts, s.executor = cat, targets, charts, executor
	return s
}

// WithGate is intended for contract tests and for the independently confirmed
// renderer handoff. No configuration flag enables the production gate.
func (s *Service) WithGate(gate GateStatus) *Service {
	s.gate = gate
	return s
}

type grafanaTargetConfig struct {
	BaseURL        string                   `json:"baseUrl"`
	Evaluation     observability.Evaluation `json:"evaluation"`
	FolderPrefixes []string                 `json:"folderPrefixes"`
	Datasources    []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"datasources"`
}

func targetConfig(target resourcetargets.Target) (grafanaTargetConfig, error) {
	var config grafanaTargetConfig
	if err := json.Unmarshal(target.Config, &config); err != nil {
		return config, err
	}
	return config, nil
}

func supportsEvaluation(capability *observability.Capability, evaluation observability.Evaluation) bool {
	if capability == nil {
		return false
	}
	for _, supported := range capability.Targets {
		if supported == evaluation {
			return true
		}
	}
	return false
}

func defaultTargetIntent(target resourcetargets.Target, capability *observability.Capability, orgSlug string) (*TargetIntent, bool) {
	config, err := targetConfig(target)
	if err != nil || !supportsEvaluation(capability, config.Evaluation) || len(config.Datasources) == 0 {
		return nil, false
	}
	folder := orgSlug + "/" + capability.Folder
	allowed := false
	for _, prefix := range config.FolderPrefixes {
		if folder == prefix || strings.HasPrefix(folder, prefix+"/") {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, false
	}
	selection, _ := json.Marshal(map[string]any{"folder": folder, "datasource": config.Datasources[0].Name, "evaluation": config.Evaluation})
	return &TargetIntent{ID: target.ID, Revision: target.Revision, Selection: selection}, true
}

func (s *Service) existingRequest(ctx context.Context, req PlanRequest, orgID string) (PlanRequest, *Plan, error) {
	if req.Operation != OperationProvisionExisting {
		return req, nil, nil
	}
	if req.InstanceID == "" {
		return req, nil, errors.New("instanceId is required for existing-instance provisioning")
	}
	original, err := s.store.LatestPlanForInstance(ctx, orgID, req.InstanceID)
	if err != nil {
		return req, nil, err
	}
	req.Source = &original.Source
	req.Deployment = original.Deployment
	return req, original, nil
}

func (s *Service) Preflight(ctx context.Context, req PlanRequest, orgID, orgSlug, subject string) (*Preflight, error) {
	if s.targets == nil {
		return nil, errors.New("resource target resolver is not configured")
	}
	req, original, err := s.existingRequest(ctx, req, orgID)
	if err != nil {
		return nil, err
	}
	if req.Operation == "" {
		req.Operation = OperationDeploy
	}
	var appTarget *resourcetargets.ResolvedTarget
	if req.Deployment.TargetID != "" {
		appTarget, err = s.targets.Resolve(ctx, resourcetargets.ResolveInput{OrgID: orgID, Subject: subject, TargetID: req.Deployment.TargetID, Capability: resourcetargets.CapabilityDeploymentCluster, Action: resourcetargets.ActionUse, ExpectedRevision: req.Deployment.TargetRevision, Selection: json.RawMessage(`{}`)})
		if err != nil {
			return nil, err
		}
	}
	normalized, err := s.normalizeSource(ctx, req, orgID, appTarget)
	if err != nil {
		return nil, err
	}
	if normalized.capability != nil {
		if err := normalized.capability.ValidateAppVersion(normalized.app.Version); err != nil {
			return nil, err
		}
	}
	if original != nil {
		if original.App.Version != normalized.app.Version || original.App.Digest != normalized.app.Digest || original.CapabilityDigest != normalized.capabilityDigest {
			return nil, errors.New("original application pin or capability changed; review a fresh deployment plan")
		}
	}
	now := s.now()
	plan := &Plan{
		ID: s.newID(), OrgID: orgID, OrgSlug: orgSlug, Requester: subject, IdempotencyKey: req.IdempotencyKey,
		Operation: req.Operation, Source: normalized.source, Deployment: req.Deployment, App: normalized.app,
		Capability: normalized.capability, CapabilityDigest: normalized.capabilityDigest, Gate: s.gate,
		State: "preflight", AppClusterID: req.Deployment.TargetID, CreatedAt: now, UpdatedAt: now,
	}
	if appTarget != nil && appTarget.Cluster != nil {
		plan.AppClusterID = appTarget.Cluster.ID
	}
	if original != nil {
		plan.AppInstanceID = original.AppInstanceID
		plan.ScaffoldRunID = original.ScaffoldRunID
	}
	plan.Observability = req.Observability
	if plan.Capability == nil {
		plan.Observability.Mode = ModeNone
	} else if plan.Observability.Mode == "" {
		plan.Observability.Mode = ModeSkip
	}
	if plan.Observability.Mode != ModeNone && plan.Observability.Mode != ModeSkip && plan.Observability.Mode != ModeProvision {
		return nil, errors.New("observability mode must be none, skip, or provision")
	}
	if normalized.managedChart && plan.Capability != nil {
		overlaid, err := ApplyManagedChartOverlay(plan.Deployment.Spec)
		if err != nil {
			return nil, err
		}
		plan.RenderIntent = &RenderIntent{AppSpec: overlaid}
	}
	deploymentTargets, err := s.targets.List(ctx, orgID, subject, resourcetargets.ListFilter{Capability: resourcetargets.CapabilityDeploymentCluster, Action: resourcetargets.ActionUse})
	if err != nil {
		return nil, err
	}
	monitoringTargets := []resourcetargets.Target{}
	if plan.Capability != nil {
		candidates, err := s.targets.List(ctx, orgID, subject, resourcetargets.ListFilter{Capability: resourcetargets.CapabilityMonitoringGrafana, Action: resourcetargets.ActionProvision})
		if err != nil {
			return nil, err
		}
		for _, target := range candidates {
			config, err := targetConfig(target)
			if err == nil && supportsEvaluation(plan.Capability, config.Evaluation) {
				monitoringTargets = append(monitoringTargets, target)
			}
		}
	}
	packs, err := s.compatiblePacks(ctx, normalized)
	if err != nil {
		return nil, err
	}
	if plan.Observability.Mode == ModeProvision {
		if plan.Observability.Pack == nil && len(packs) > 0 {
			pin := packs[0]
			plan.Observability.Pack = &pin
		}
		if plan.Observability.Target == nil {
			for _, target := range monitoringTargets {
				config, _ := targetConfig(target)
				if !target.IsDefault || config.Evaluation != observability.EvaluationCentral {
					continue
				}
				if selected, ok := defaultTargetIntent(target, plan.Capability, orgSlug); ok {
					plan.Observability.Target = selected
					break
				}
			}
		}
		if plan.Observability.Target != nil && len(plan.Observability.Target.Selection) > 0 {
			intent, err := BuildPackRenderIntent(plan.Capability, plan.Observability.Target.Selection, orgSlug, plan.Deployment.OwnerTeam)
			if err != nil {
				return nil, err
			}
			if plan.RenderIntent == nil {
				plan.RenderIntent = &RenderIntent{}
			}
			plan.RenderIntent.PackSpec = intent.PackSpec
			plan.RenderIntent.Evaluation = intent.Evaluation
		}
	}
	fingerprintInput := plan.DeepCopy()
	fingerprintInput.ID = ""
	fingerprintInput.PlanFingerprint = ""
	fingerprintInput.State = ""
	fingerprintInput.CreatedAt = time.Time{}
	fingerprintInput.UpdatedAt = time.Time{}
	plan.PlanFingerprint, err = Fingerprint(fingerprintInput)
	if err != nil {
		return nil, err
	}
	return &Preflight{Plan: *plan, DeploymentTargets: deploymentTargets, MonitoringTargets: monitoringTargets, CompatiblePacks: packs, Providers: s.targets.Providers()}, nil
}

func (s *Service) Submit(ctx context.Context, req PlanRequest, orgID, orgSlug, subject string) (*Plan, error) {
	preflight, err := s.Preflight(ctx, req, orgID, orgSlug, subject)
	if err != nil {
		return nil, err
	}
	plan := preflight.Plan.DeepCopy()
	if req.PlanFingerprint != "" && req.PlanFingerprint != plan.PlanFingerprint {
		return nil, fmt.Errorf("%w: plan_stale", ErrPlanConflict)
	}
	if req.IdempotencyKey != "" {
		existing, err := s.store.GetPlanByIdempotency(ctx, orgID, subject, req.IdempotencyKey)
		if err == nil {
			if existing.PlanFingerprint != plan.PlanFingerprint {
				return nil, fmt.Errorf("%w: idempotency key reused with different plan", ErrPlanConflict)
			}
			return existing, nil
		}
		if !errors.Is(err, ErrPlanNotFound) {
			return nil, err
		}
	}
	plan.State = "submitted"
	if plan.Observability.Mode == ModeProvision {
		if plan.Observability.Pack == nil || plan.Observability.Target == nil {
			return nil, errors.New("provision requires an exact compatible pack and monitoring target")
		}
		resolved, err := s.targets.Resolve(ctx, resourcetargets.ResolveInput{OrgID: orgID, Subject: subject, TargetID: plan.Observability.Target.ID, Capability: resourcetargets.CapabilityMonitoringGrafana, Action: resourcetargets.ActionProvision, ExpectedRevision: plan.Observability.Target.Revision, Selection: plan.Observability.Target.Selection})
		if err != nil {
			return nil, err
		}
		intent, err := BuildPackRenderIntent(plan.Capability, resolved.Selection, orgSlug, plan.Deployment.OwnerTeam)
		if err != nil {
			return nil, err
		}
		plan.RenderIntent.PackSpec = intent.PackSpec
		plan.RenderIntent.Evaluation = intent.Evaluation
		if resolved.Cluster == nil {
			return nil, errors.New("monitoring target returned no cluster")
		}
		pack := plan.Observability.Pack
		if err := s.catalog.EnsureVisible(ctx, orgID, resolved.Cluster.ID, pack.ItemID); err != nil {
			return nil, err
		}
		admitted, err := s.catalog.AdmitVersion(ctx, pack.ItemID, pack.Version, environmentFor(resolved))
		if err != nil {
			return nil, err
		}
		if admitted == nil || admitted.Version == nil || admitted.Version.ArtifactDigest != pack.Digest {
			return nil, errors.New("observability pack digest mismatch")
		}
		companionState := "waiting_for_app"
		if !s.gate.CompanionRendering {
			companionState = "blocked_external_gate"
		} else if resolved.Approval.Required {
			companionState = "approval_pending"
		}
		now := s.now()
		companion := &Companion{
			ID: s.newID(), PlanID: plan.ID, AppInstanceID: plan.AppInstanceID, ScaffoldRunID: plan.ScaffoldRunID,
			TargetID: resolved.Target.ID, TargetRevision: resolved.Target.Revision, TargetClusterID: resolved.Cluster.ID, TargetSelection: resolved.Selection,
			AppSourceDigest: plan.App.Digest, AppRevision: plan.App.Version + "@" + plan.App.Digest, Pack: *pack,
			CapabilityDigest: plan.CapabilityDigest, State: companionState, Generation: 1, Links: []Link{}, CreatedAt: now, UpdatedAt: now,
		}
		if companionState == "blocked_external_gate" {
			companion.Reason = s.gate.Reason
		}
		plan.Companion = companion
	}
	if err := s.store.CreatePlan(ctx, plan); err != nil {
		return nil, err
	}
	if req.Operation == OperationProvisionExisting {
		return plan, nil
	}
	if s.executor == nil {
		return nil, errors.New("application executor is not configured")
	}
	if plan.RenderIntent != nil && len(plan.RenderIntent.AppSpec) > 0 {
		plan.Deployment.Spec = plan.RenderIntent.AppSpec
	}
	instanceID, runID, err := s.executor.Execute(ctx, orgID, subject, plan)
	if err != nil {
		plan.State = "failed"
		plan.ErrorCode = "application_execution_failed"
		plan.ErrorMessage = err.Error()
		plan.UpdatedAt = s.now()
		_ = s.store.UpdatePlan(ctx, plan)
		return nil, err
	}
	plan.AppInstanceID, plan.ScaffoldRunID = instanceID, runID
	plan.UpdatedAt = s.now()
	if plan.Companion != nil {
		plan.Companion.AppInstanceID = instanceID
		plan.Companion.ScaffoldRunID = runID
		plan.Companion.UpdatedAt = plan.UpdatedAt
	}
	if err := s.store.UpdatePlan(ctx, plan); err != nil {
		return nil, err
	}
	return plan, nil
}

func (s *Service) Get(ctx context.Context, orgID, id, subject string) (*Plan, error) {
	plan, err := s.store.GetPlan(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	if plan.AppInstanceID != "" {
		status, err := s.InstanceObservability(ctx, orgID, plan.AppInstanceID, subject)
		if err == nil {
			plan.Companion = status.Companion
		}
	}
	return plan, nil
}

func selectedDatasource(companion *Companion) string {
	var selection struct {
		Datasource string `json:"datasource"`
	}
	if err := json.Unmarshal(companion.TargetSelection, &selection); err != nil {
		return ""
	}
	return selection.Datasource
}

func (s *Service) InstanceObservability(ctx context.Context, orgID, instanceID, subject string) (*InstanceObservability, error) {
	plan, err := s.store.LatestPlanForInstance(ctx, orgID, instanceID)
	if err != nil {
		return nil, err
	}
	out := &InstanceObservability{Mode: plan.Observability.Mode, Available: plan.Capability != nil}
	if !out.Available {
		out.Reason = "This exact app version has no signed observability metadata."
	}
	companion, err := s.store.LatestCompanionForInstance(ctx, orgID, instanceID)
	if errors.Is(err, ErrCompanionNotFound) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	out.Companion = companion
	companion.Links = []Link{}
	if companion.State != "ready" || companion.Verification == nil || plan.Capability == nil {
		return out, nil
	}
	target, err := s.targets.Get(ctx, orgID, subject, companion.TargetID)
	if err != nil {
		companion.Reason = "target_unavailable"
		return out, nil
	}
	view := false
	for _, action := range target.EffectiveActions {
		view = view || action == resourcetargets.ActionView
	}
	if !view {
		companion.Reason = "target_unavailable"
		return out, nil
	}
	values := map[string]string{
		"namespace": plan.Deployment.Namespace, "instance": plan.Deployment.Name, "app": plan.Capability.App,
		"org": plan.OrgSlug, "cluster": plan.AppClusterID, "datasource": selectedDatasource(companion),
	}
	if values["instance"] == "" {
		values["instance"] = instanceID
	}
	links, err := VerifiedLinks(*target, plan.Capability, companion.Verification, values, s.now())
	if err != nil {
		return nil, err
	}
	companion.Links = links
	return out, nil
}

func (s *Service) ApplyVerification(ctx context.Context, orgID string, result *observability.VerificationResult) (*Companion, error) {
	if result == nil {
		return nil, errors.New("verification result is required")
	}
	companion, err := s.store.GetCompanion(ctx, orgID, result.Companion.ID)
	if err != nil {
		return nil, err
	}
	if companion.CompanionInstanceID == "" || (companion.State != "verification_pending" && companion.State != "deploying" && companion.State != "verification_failed" && companion.State != "ready") {
		return nil, errors.New("verification_unavailable")
	}
	plan, err := s.store.GetPlan(ctx, orgID, companion.PlanID)
	if err != nil {
		return nil, err
	}
	if result.Companion.Generation != companion.Generation || result.Target.ID != companion.TargetID || result.Target.Revision != companion.TargetRevision || result.Target.ClusterID != companion.TargetClusterID ||
		result.App.PlanID != plan.ID || result.App.SourceDigest != companion.AppSourceDigest || result.App.Revision != companion.AppRevision ||
		result.Pack.ItemID != companion.Pack.ItemID || result.Pack.Version != companion.Pack.Version || result.Pack.Digest != companion.Pack.Digest || result.CapabilityDigest != companion.CapabilityDigest {
		return nil, errors.New("verification_stale")
	}
	if companion.AppInstanceID != "" && result.App.InstanceID != companion.AppInstanceID {
		return nil, errors.New("verification_stale")
	}
	if companion.ScaffoldRunID != "" && result.App.ScaffoldRunID != companion.ScaffoldRunID {
		return nil, errors.New("verification_stale")
	}
	if err := result.ValidateAt(s.now()); err != nil {
		return nil, err
	}
	companion.Verification = result
	companion.State = "verification_failed"
	if result.Result == "passed" {
		companion.State = "ready"
	}
	companion.Links = []Link{}
	companion.UpdatedAt = s.now()
	if err := s.store.SaveVerification(ctx, companion.ID, result); err != nil {
		return nil, err
	}
	plan.Companion = companion
	plan.UpdatedAt = companion.UpdatedAt
	if err := s.store.UpdatePlan(ctx, plan); err != nil {
		return nil, err
	}
	return companion, nil
}
