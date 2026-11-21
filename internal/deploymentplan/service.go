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
	"github.com/7K-Inari/inari-server/internal/inventory"
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
	Execute(ctx context.Context, orgID, subject string, plan *Plan) (*Execution, error)
}

type InstanceResolver interface {
	Get(ctx context.Context, orgID, id string) (*inventory.InstanceView, error)
}

type TeamLister interface {
	ListTeams(ctx context.Context, orgID string) ([]types.Team, error)
}

type TeamListerFunc func(context.Context, string) ([]types.Team, error)

func (f TeamListerFunc) ListTeams(ctx context.Context, orgID string) ([]types.Team, error) {
	return f(ctx, orgID)
}

type Service struct {
	db        *db.DB
	store     Store
	catalog   Catalog
	targets   Targets
	charts    ChartFetcher
	executor  AppExecutor
	instances InstanceResolver
	teams     TeamLister
	gate      GateStatus
	now       func() time.Time
	newID     func() string
}

func NewService(d *db.DB, store Store) *Service {
	return &Service{db: d, store: store, now: time.Now, newID: func() string { return uuid.NewString() }, gate: GateStatus{Reason: "sibling_8f8c472a_phase_3_unconfirmed"}}
}

func (s *Service) WithDependencies(cat Catalog, targets Targets, charts ChartFetcher, executor AppExecutor) *Service {
	s.catalog, s.targets, s.charts, s.executor = cat, targets, charts, executor
	return s
}

func (s *Service) WithInstances(instances InstanceResolver) *Service {
	s.instances = instances
	return s
}

func (s *Service) WithTeams(teams TeamLister) *Service {
	s.teams = teams
	return s
}

func (s *Service) validateOwnerTeam(ctx context.Context, orgID, ownerTeam string) error {
	if ownerTeam == "" {
		return errors.New("ownerTeam is required for observability provisioning")
	}
	if s.teams == nil {
		return errors.New("team resolver is not configured")
	}
	teams, err := s.teams.ListTeams(ctx, orgID)
	if err != nil {
		return err
	}
	for _, team := range teams {
		if team.ID == ownerTeam || team.Name == ownerTeam {
			return nil
		}
	}
	return errors.New("ownerTeam must be a team in the current org")
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

func templateNamespace(orgSlug, component string) string {
	namespace := orgSlug + "--" + component
	if len(namespace) <= 63 {
		return namespace
	}
	keep := 63 - len(orgSlug) - 2
	if keep < 1 {
		return strings.TrimRight(orgSlug[:63], "-")
	}
	return namespace[:len(orgSlug)+2] + strings.TrimRight(component[:keep], "-")
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

func (s *Service) existingRequest(ctx context.Context, req PlanRequest, orgID, subject string) (PlanRequest, *Plan, error) {
	if req.Operation != OperationProvisionExisting {
		return req, nil, nil
	}
	if req.InstanceID == "" {
		return req, nil, errors.New("instanceId is required for existing-instance provisioning")
	}
	original, err := s.store.LatestPlanForInstance(ctx, orgID, req.InstanceID)
	if err == nil {
		req.Source = &original.Source
		req.Deployment = original.Deployment
		return req, original, nil
	}
	if !errors.Is(err, ErrPlanNotFound) || s.instances == nil {
		return req, nil, err
	}
	instance, err := s.instances.Get(ctx, orgID, req.InstanceID)
	if err != nil {
		return req, nil, err
	}
	if instance.ArtifactDigest == "" {
		return req, nil, errors.New("capability_unavailable: legacy instance has no recorded artifact digest")
	}
	targets, err := s.targets.List(ctx, orgID, subject, resourcetargets.ListFilter{Capability: resourcetargets.CapabilityDeploymentCluster, Action: resourcetargets.ActionUse, ResourceRef: &resourcetargets.TargetResourceRef{Kind: resourcetargets.ResourceKindCluster, ID: instance.ClusterID}})
	if err != nil || len(targets) == 0 {
		return req, nil, errors.New("capability_unavailable: legacy instance has no entitled deployment target")
	}
	target := targets[0]
	name := instance.ResourceRef.Name
	if name == "" {
		name = instance.ID
	}
	original = &Plan{
		OrgID: orgID, Operation: OperationDeploy, Source: Source{Kind: SourceCatalog, ItemID: instance.CatalogItemID, Version: instance.Version},
		App: ArtifactPin{ItemID: instance.CatalogItemID, Version: instance.Version, Digest: instance.ArtifactDigest}, AppInstanceID: instance.ID,
		Deployment:    DeploymentInput{TargetID: target.ID, TargetRevision: target.Revision, RepoID: instance.RepoID, Name: name, Namespace: instance.ResourceRef.Namespace, OwnerTeam: instance.OwnerTeam, Spec: instance.Spec, DisplayName: name},
		Observability: ObservabilityInput{Mode: ModeSkip}, CreatedAt: instance.CreatedAt, UpdatedAt: instance.UpdatedAt,
	}
	req.Source = &original.Source
	req.Deployment = original.Deployment
	return req, original, nil
}

func (s *Service) Preflight(ctx context.Context, req PlanRequest, orgID, orgSlug, subject string) (*Preflight, error) {
	if s.targets == nil {
		return nil, errors.New("resource target resolver is not configured")
	}
	req, original, err := s.existingRequest(ctx, req, orgID, subject)
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
		if original.App.Version != normalized.app.Version || original.App.Digest != normalized.app.Digest || (original.CapabilityDigest != "" && original.CapabilityDigest != normalized.capabilityDigest) {
			return nil, errors.New("original application pin or capability changed; review a fresh deployment plan")
		}
	}
	deployment := req.Deployment
	if normalized.source.Kind == SourceTemplate && deployment.Name != "" {
		if deployment.OwnerTeam == "" {
			deployment.OwnerTeam = deployment.Name + "-maintainers"
		}
		if deployment.Namespace == "" {
			deployment.Namespace = templateNamespace(orgSlug, deployment.Name)
		}
	}
	now := s.now()
	plan := &Plan{
		ID: s.newID(), OrgID: orgID, OrgSlug: orgSlug, Requester: subject, IdempotencyKey: req.IdempotencyKey,
		Operation: req.Operation, Source: normalized.source, Deployment: deployment, App: normalized.app,
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
	if plan.Observability.Mode == ModeProvision && plan.Deployment.OwnerTeam != "" {
		if err := s.validateOwnerTeam(ctx, orgID, plan.Deployment.OwnerTeam); err != nil {
			return nil, err
		}
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
		if plan.Observability.Target != nil && len(plan.Observability.Target.Selection) > 0 && plan.Deployment.OwnerTeam != "" {
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
	return &Preflight{Plan: *plan, Schema: normalized.version.Schema, UIHints: normalized.version.UIHints, DeploymentTargets: deploymentTargets, MonitoringTargets: monitoringTargets, CompatiblePacks: packs, Providers: s.targets.Providers()}, nil
}

func (s *Service) Submit(ctx context.Context, req PlanRequest, orgID, orgSlug, subject string) (*Plan, error) {
	if req.PlanFingerprint == "" {
		return nil, fmt.Errorf("%w: plan_stale: planFingerprint is required", ErrPlanConflict)
	}
	if req.Operation != OperationProvisionExisting {
		if req.Source == nil || req.Source.Version == "" || req.Source.Digest == "" {
			return nil, fmt.Errorf("%w: plan_stale: exact normalized source version and digest are required", ErrPlanConflict)
		}
	}
	preflight, err := s.Preflight(ctx, req, orgID, orgSlug, subject)
	if err != nil {
		return nil, err
	}
	plan := preflight.Plan.DeepCopy()
	if req.PlanFingerprint != plan.PlanFingerprint {
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
		if err := s.validateOwnerTeam(ctx, orgID, plan.Deployment.OwnerTeam); err != nil {
			return nil, err
		}
		if plan.Observability.Pack == nil || plan.Observability.Target == nil {
			return nil, errors.New("provision requires an exact compatible pack and monitoring target")
		}
		pack := plan.Observability.Pack
		compatible := false
		for _, candidate := range preflight.CompatiblePacks {
			if *pack == candidate {
				compatible = true
				break
			}
		}
		if !compatible {
			return nil, fmt.Errorf("%w: selected pack is not an exact compatible preflight candidate", resourcetargets.ErrInvalidInput)
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
		if err := s.catalog.EnsureVisible(ctx, orgID, resolved.Cluster.ID, pack.ItemID); err != nil {
			return nil, err
		}
		admitted, err := s.catalog.AdmitVersion(ctx, pack.ItemID, pack.Version, environmentFor(resolved))
		if err != nil {
			return nil, err
		}
		if admitted == nil || admitted.Version == nil {
			return nil, errors.New("observability pack admission returned no version")
		}
		version := admitted.Version
		if version.ItemID != pack.ItemID || version.Version != pack.Version || version.PackageVersion != pack.PackageVersion ||
			version.ArtifactRef != pack.Ref || version.ArtifactDigest != pack.Digest || version.ChartRef != pack.ChartRef || version.ChartDigest != pack.ChartDigest {
			return nil, fmt.Errorf("%w: admitted observability pack pin differs from the selected candidate", resourcetargets.ErrInvalidInput)
		}
		item, err := s.catalog.GetItemByID(ctx, pack.ItemID)
		if err != nil {
			return nil, err
		}
		if item.SourceID != pack.SourceID || item.Category != "observability" || packType(version) != "kro-rgd" {
			return nil, fmt.Errorf("%w: admitted pack is not a same-source kro-rgd observability candidate", resourcetargets.ErrInvalidInput)
		}
		if err := plan.Capability.ValidatePackVersion(version.Version); err != nil {
			return nil, err
		}
		if err := ValidatePackRGD(packRGD(version), *pack, plan.Capability); err != nil {
			return nil, err
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
	execution, err := s.executor.Execute(ctx, orgID, subject, plan)
	if err != nil {
		plan.State = "failed"
		plan.ErrorCode = "application_execution_failed"
		plan.ErrorMessage = err.Error()
		plan.UpdatedAt = s.now()
		_ = s.store.UpdatePlan(ctx, plan)
		return nil, err
	}
	plan.AppInstanceID, plan.ScaffoldRunID = execution.InstanceID, execution.ScaffoldRunID
	plan.CommitSHA, plan.PRURL, plan.ApprovalID = execution.CommitSHA, execution.PRURL, execution.ApprovalID
	plan.UpdatedAt = s.now()
	if plan.Companion != nil {
		plan.Companion.AppInstanceID = execution.InstanceID
		plan.Companion.ScaffoldRunID = execution.ScaffoldRunID
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
		if err == nil && status.Companion != nil && status.Companion.PlanID == plan.ID {
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

func (s *Service) unplannedInstanceObservability(ctx context.Context, orgID, instanceID string) (*InstanceObservability, error) {
	if s.instances == nil {
		return nil, ErrPlanNotFound
	}
	instance, err := s.instances.Get(ctx, orgID, instanceID)
	if err != nil {
		return nil, err
	}
	if instance.CatalogItemID == "" || instance.Version == "" || instance.ArtifactDigest == "" {
		return &InstanceObservability{Mode: ModeNone, Available: false, Reason: "capability_unavailable: original application pin is incomplete"}, nil
	}
	source := Source{Kind: SourceCatalog, ItemID: instance.CatalogItemID, Version: instance.Version, Digest: instance.ArtifactDigest}
	normalized, err := s.normalizeSource(ctx, PlanRequest{Source: &source}, orgID, nil)
	if err != nil {
		return nil, err
	}
	if normalized.app.Digest != instance.ArtifactDigest {
		return &InstanceObservability{Mode: ModeNone, Available: false, Reason: "capability_unavailable: original application digest does not match"}, nil
	}
	out := &InstanceObservability{Mode: ModeNone, Available: normalized.capability != nil}
	if normalized.capability != nil {
		if err := normalized.capability.ValidateAppVersion(normalized.app.Version); err != nil {
			return nil, err
		}
		out.Mode = ModeSkip
	} else {
		out.Reason = "This exact app version has no signed observability metadata."
	}
	return out, nil
}

func (s *Service) InstanceObservability(ctx context.Context, orgID, instanceID, subject string) (*InstanceObservability, error) {
	plan, err := s.store.LatestPlanForInstance(ctx, orgID, instanceID)
	if errors.Is(err, ErrPlanNotFound) {
		return s.unplannedInstanceObservability(ctx, orgID, instanceID)
	}
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
	if companion.PlanID != plan.ID {
		return out, nil
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
	if err := validateReadyEvidence(plan, companion, target, companion.Verification); err != nil {
		companion.Reason = "verification_stale"
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
	expectedVerification := verificationToken(companion.Verification)
	if companion.Verification != nil {
		if expectedVerification == verificationToken(result) {
			return companion, nil
		}
		if !result.Run.FinishedAt.After(companion.Verification.Run.FinishedAt) {
			return nil, errors.New("verification_stale: out-of-order evidence")
		}
	}
	if err := result.ValidateAt(s.now()); err != nil {
		return nil, err
	}
	if result.Result == "passed" {
		target, err := s.targets.Get(ctx, orgID, plan.Requester, companion.TargetID)
		if err != nil {
			return nil, fmt.Errorf("verification target unavailable: %w", err)
		}
		if err := validateReadyEvidence(plan, companion, target, result); err != nil {
			return nil, err
		}
	}
	companion.Verification = result
	companion.State = "verification_failed"
	if result.Result == "passed" {
		companion.State = "ready"
	}
	companion.Links = []Link{}
	companion.UpdatedAt = s.now()
	applied, err := s.store.SaveVerification(ctx, orgID, companion, result, expectedVerification)
	if err != nil {
		return nil, err
	}
	if !applied {
		return s.store.GetCompanion(ctx, orgID, companion.ID)
	}
	return companion, nil
}
