package resourcetargets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/clusterregistry"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/impersonation"
	"github.com/7K-Inari/inari-server/internal/types"
)

type ClusterGetter interface {
	GetCluster(ctx context.Context, id string) (*types.Cluster, error)
}

type InventorySource interface {
	BaselineRepoSelector(ctx context.Context, q db.Querier, orgID, clusterID string) (string, error)
	GetGitRepo(ctx context.Context, q db.Querier, orgID, id string) (*types.TenantGitRepo, error)
	ListClusterAddons(ctx context.Context, q db.Querier, orgID, clusterID string) ([]*types.ClusterAddon, error)
}

type CapabilitySource interface {
	List(ctx context.Context, q db.Querier, clusterID string) ([]types.Capability, error)
}

type TeamLister interface {
	ListTeams(ctx context.Context, orgID string) ([]types.Team, error)
}

type Sources struct {
	Clusters     ClusterGetter
	Inventory    InventorySource
	Capabilities CapabilitySource
	Teams        TeamLister
}

type Service struct {
	db       *db.DB
	store    *Store
	registry *Registry
	authz    authz.Authorizer
	audit    *audit.Store
	sources  Sources
}

func NewService(d *db.DB, store *Store, registry *Registry, az authz.Authorizer, auditStore *audit.Store, sources Sources) *Service {
	if registry == nil {
		registry = DefaultRegistry()
	}
	return &Service{db: d, store: store, registry: registry, authz: az, audit: auditStore, sources: sources}
}

func (s *Service) Providers() []ProviderDescriptor { return s.registry.Descriptors() }

func (s *Service) provider(capability string) (Provider, error) {
	p, ok := s.registry.Provider(capability)
	if !ok {
		return nil, invalid("capability", "no provider is registered for "+capability)
	}
	return p, nil
}

func validateTargetInput(p Provider, in CreateInput) error {
	if strings.TrimSpace(in.Name) == "" {
		return invalid("name", "name is required")
	}
	if in.ResourceRef.ID == "" {
		return invalid("resourceRef.id", "resource ID is required")
	}
	supported := false
	for _, kind := range p.Describe().ResourceKinds {
		if kind == in.ResourceRef.Kind {
			supported = true
			break
		}
	}
	if !supported {
		return invalid("resourceRef.kind", "provider does not support this resource kind")
	}
	if in.IsDefault && !p.Describe().SupportsDefault {
		return invalid("isDefault", "provider does not support org defaults")
	}
	return nil
}

func (s *Service) Create(ctx context.Context, orgID, actor string, in CreateInput) (*Target, error) {
	p, err := s.provider(in.Capability)
	if err != nil {
		return nil, err
	}
	in.Name = strings.TrimSpace(in.Name)
	if err := validateTargetInput(p, in); err != nil {
		return nil, err
	}
	config, err := p.NormalizeConfig(in.Config)
	if err != nil {
		return nil, err
	}
	target := &Target{
		OrgID: orgID, Name: in.Name, ResourceRef: in.ResourceRef, Capabilities: []string{in.Capability},
		Config: config, Enabled: true, IsDefault: in.IsDefault, Revision: 1, CreatedBy: actor,
	}
	snapshot, err := s.loadSnapshot(ctx, target)
	if err != nil {
		return nil, err
	}
	if err := p.ValidateRegistration(snapshot, config); err != nil {
		return nil, err
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if target.IsDefault {
			if err := s.store.ClearDefault(ctx, tx, orgID, in.Capability, ""); err != nil {
				return err
			}
		}
		if err := s.store.Create(ctx, tx, target); err != nil {
			return err
		}
		if err := s.recordAudit(ctx, tx, orgID, actor, "resource_target.created", target.ID, map[string]any{
			"capability": in.Capability, "resourceKind": in.ResourceRef.Kind, "resourceId": in.ResourceRef.ID, "revision": target.Revision,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, orgID, types.EventResourceTargetCreated, types.ResourceTargetPayload{OrgID: orgID, TargetID: target.ID})
	})
	if err != nil {
		return nil, err
	}
	return target, nil
}

func (s *Service) Update(ctx context.Context, orgID, targetID, actor string, in PatchInput) (*Target, error) {
	if in.Revision <= 0 {
		return nil, invalid("revision", "current revision is required")
	}
	target, err := s.store.Get(ctx, s.db.Pool, orgID, targetID)
	if err != nil {
		return nil, err
	}
	if in.Name == nil && in.Config == nil && in.Enabled == nil && in.IsDefault == nil {
		return target, nil
	}
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" {
			return nil, invalid("name", "name is required")
		}
		target.Name = name
	}
	if in.Config != nil {
		target.Config = *in.Config
	}
	if in.Enabled != nil {
		target.Enabled = *in.Enabled
	}
	if in.IsDefault != nil {
		target.IsDefault = *in.IsDefault
	}
	p, err := s.provider(target.Capability())
	if err != nil {
		return nil, err
	}
	config, err := p.NormalizeConfig(target.Config)
	if err != nil {
		return nil, err
	}
	target.Config = config
	if target.IsDefault && !p.Describe().SupportsDefault {
		return nil, invalid("isDefault", "provider does not support org defaults")
	}
	snapshot, err := s.loadSnapshot(ctx, target)
	if err != nil {
		return nil, err
	}
	if err := p.ValidateRegistration(snapshot, target.Config); err != nil {
		return nil, err
	}
	previousRevision := target.Revision
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if target.IsDefault {
			if err := s.store.ClearDefault(ctx, tx, orgID, target.Capability(), target.ID); err != nil {
				return err
			}
		}
		if err := s.store.Update(ctx, tx, target, in.Revision); err != nil {
			return err
		}
		if err := s.recordAudit(ctx, tx, orgID, actor, "resource_target.updated", target.ID, map[string]any{
			"capability": target.Capability(), "previousRevision": previousRevision, "revision": target.Revision,
			"enabled": target.Enabled, "isDefault": target.IsDefault,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, orgID, types.EventResourceTargetUpdated, types.ResourceTargetPayload{OrgID: orgID, TargetID: target.ID})
	})
	if err != nil {
		return nil, err
	}
	return target, nil
}

func (s *Service) Delete(ctx context.Context, orgID, targetID, actor string) error {
	target, err := s.store.Get(ctx, s.db.Pool, orgID, targetID)
	if err != nil {
		return err
	}
	grants, err := s.store.ListGrants(ctx, s.db.Pool, orgID, targetID)
	if err != nil {
		return err
	}
	snapshot := make([]types.ResourceTargetGrant, 0, len(grants))
	for _, grant := range grants {
		snapshot = append(snapshot, types.ResourceTargetGrant{TargetID: targetID, TeamID: grant.TeamID, Relation: string(grant.Relation)})
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.Delete(ctx, tx, orgID, targetID); err != nil {
			return err
		}
		if err := s.recordAudit(ctx, tx, orgID, actor, "resource_target.deleted", target.ID, map[string]any{
			"capability": target.Capability(), "resourceKind": target.ResourceRef.Kind, "resourceId": target.ResourceRef.ID,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, orgID, types.EventResourceTargetDeleted, types.ResourceTargetPayload{
			OrgID: orgID, TargetID: targetID, Deleted: true, Grants: snapshot,
		})
	})
}

func actionSupported(p Provider, action Action) bool {
	for _, candidate := range p.Describe().Actions {
		if candidate == action {
			return true
		}
	}
	return false
}

func (s *Service) SetGrant(ctx context.Context, orgID, targetID, teamID string, relation Action, actor string) (*Grant, error) {
	target, err := s.store.Get(ctx, s.db.Pool, orgID, targetID)
	if err != nil {
		return nil, err
	}
	p, err := s.provider(target.Capability())
	if err != nil {
		return nil, err
	}
	if !relation.Valid() || !actionSupported(p, relation) {
		return nil, invalid("relation", "provider does not support this grant")
	}
	teams, err := s.sources.Teams.ListTeams(ctx, orgID)
	if err != nil {
		return nil, err
	}
	teamFound := false
	for _, team := range teams {
		if team.ID == teamID {
			teamFound = true
			break
		}
	}
	if !teamFound {
		return nil, invalid("teamId", "team must belong to the org")
	}
	var previous Action
	if old, err := s.store.GetGrant(ctx, s.db.Pool, orgID, targetID, teamID); err == nil {
		previous = old.Relation
	} else if !errors.Is(err, ErrTargetNotFound) {
		return nil, err
	}
	grant := &Grant{TargetID: targetID, TeamID: teamID, Relation: relation, CreatedBy: actor}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.SetGrant(ctx, tx, grant); err != nil {
			return err
		}
		if err := s.recordAudit(ctx, tx, orgID, actor, "resource_target.grant_changed", targetID, map[string]any{
			"teamId": teamID, "oldRelation": previous, "newRelation": relation,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, orgID, types.EventResourceTargetGrantChanged, types.ResourceTargetPayload{OrgID: orgID, TargetID: targetID})
	})
	return grant, err
}

func (s *Service) RevokeGrant(ctx context.Context, orgID, targetID, teamID, actor string) error {
	old, err := s.store.GetGrant(ctx, s.db.Pool, orgID, targetID, teamID)
	if errors.Is(err, ErrTargetNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.DeleteGrant(ctx, tx, orgID, targetID, teamID); err != nil {
			return err
		}
		if err := s.recordAudit(ctx, tx, orgID, actor, "resource_target.grant_changed", targetID, map[string]any{
			"teamId": teamID, "oldRelation": old.Relation, "newRelation": "",
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, orgID, types.EventResourceTargetGrantChanged, types.ResourceTargetPayload{OrgID: orgID, TargetID: targetID})
	})
}

func subjectObject(subject string) string {
	return authz.UserObject(strings.TrimPrefix(subject, "user:"))
}

func relationForAction(action Action) (string, error) {
	switch action {
	case ActionView:
		return authz.RelationViewer, nil
	case ActionUse:
		return authz.RelationUse, nil
	case ActionProvision:
		return authz.RelationProvision, nil
	default:
		return "", invalid("action", "must be view, use, or provision")
	}
}

func (s *Service) isManager(ctx context.Context, orgID, subject string) (bool, error) {
	if s.authz == nil {
		return false, fmt.Errorf("resourcetargets: authorizer is not configured")
	}
	allowed, err := s.authz.Check(ctx, subjectObject(subject), authz.RelationResourceTargetsManage, authz.OrgObject(orgID))
	if err != nil {
		return false, &AuthorizationError{Err: err}
	}
	return allowed, nil
}

// authorize combines the OpenFGA decision with a current-DB narrowing fence.
// The fence never grants access by itself.
func (s *Service) authorize(ctx context.Context, orgID, subject, targetID string, action Action, manager bool) error {
	if manager {
		return nil
	}
	relation, err := relationForAction(action)
	if err != nil {
		return err
	}
	allowed, err := s.authz.Check(ctx, subjectObject(subject), relation, authz.ResourceTargetObject(targetID))
	if err != nil {
		return &AuthorizationError{Err: err}
	}
	if !allowed {
		return ErrTargetDenied
	}
	fence, err := s.store.GrantAllows(ctx, s.db.Pool, orgID, subject, []string{targetID}, action)
	if err != nil {
		return err
	}
	if !fence[targetID] {
		return ErrTargetDenied
	}
	return nil
}

func (s *Service) effectiveActions(ctx context.Context, target *Target, subject string, manager bool) ([]Action, error) {
	p, err := s.provider(target.Capability())
	if err != nil {
		return nil, err
	}
	if manager {
		return append([]Action(nil), p.Describe().Actions...), nil
	}
	var out []Action
	for _, action := range p.Describe().Actions {
		if err := s.authorize(ctx, target.OrgID, subject, target.ID, action, false); err == nil {
			out = append(out, action)
		} else if !errors.Is(err, ErrTargetDenied) {
			return nil, err
		}
	}
	return out, nil
}

func (s *Service) describe(ctx context.Context, target *Target, subject string, manager bool) (*Target, error) {
	snapshot, err := s.loadSnapshot(ctx, target)
	if err != nil {
		return nil, err
	}
	return s.describeSnapshot(ctx, target, subject, manager, snapshot)
}

func (s *Service) describeSnapshot(ctx context.Context, target *Target, subject string, manager bool, snapshot ResourceSnapshot) (*Target, error) {
	p, err := s.provider(target.Capability())
	if err != nil {
		return nil, err
	}
	out := *target
	out.Binding, out.Readiness, err = p.Resolve(target, snapshot)
	if err != nil {
		return nil, err
	}
	out.EffectiveActions, err = s.effectiveActions(ctx, target, subject, manager)
	if err != nil {
		return nil, err
	}
	if manager {
		out.Grants, err = s.store.ListGrants(ctx, s.db.Pool, target.OrgID, target.ID)
		if err != nil {
			return nil, err
		}
	}
	return &out, nil
}

func (s *Service) List(ctx context.Context, orgID, subject string, filter ListFilter) ([]Target, error) {
	if filter.Action == "" {
		filter.Action = ActionView
	}
	relation, err := relationForAction(filter.Action)
	if err != nil {
		return nil, err
	}
	targets, err := s.store.List(ctx, s.db.Pool, orgID, filter.Capability)
	if err != nil {
		return nil, err
	}
	manager, err := s.isManager(ctx, orgID, subject)
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	if !manager {
		objects, err := s.authz.ListObjects(ctx, subjectObject(subject), relation, authz.TypeResourceTarget)
		if err != nil {
			return nil, &AuthorizationError{Err: err}
		}
		var candidates []string
		for _, object := range objects {
			if id, ok := strings.CutPrefix(object, authz.TypeResourceTarget+":"); ok {
				candidates = append(candidates, id)
				allowed[id] = true
			}
		}
		allowed, err = s.store.GrantAllows(ctx, s.db.Pool, orgID, subject, candidates, filter.Action)
		if err != nil {
			return nil, err
		}
	}
	out := make([]Target, 0)
	for _, target := range targets {
		if filter.ResourceRef != nil && target.ResourceRef != *filter.ResourceRef {
			continue
		}
		if !manager && (!target.Enabled || !allowed[target.ID]) {
			continue
		}
		descriptor, err := s.describe(ctx, target, subject, manager)
		if err != nil {
			return nil, err
		}
		if !descriptor.Readiness.State.Selectable() && (filter.Action != ActionView || !filter.IncludeUnavailable) {
			continue
		}
		out = append(out, *descriptor)
	}
	return out, nil
}

func (s *Service) Get(ctx context.Context, orgID, subject, targetID string) (*Target, error) {
	target, err := s.store.Get(ctx, s.db.Pool, orgID, targetID)
	if err != nil {
		return nil, err
	}
	manager, err := s.isManager(ctx, orgID, subject)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, orgID, subject, targetID, ActionView, manager); err != nil {
		if errors.Is(err, ErrTargetDenied) {
			return nil, ErrTargetNotFound
		}
		return nil, err
	}
	return s.describe(ctx, target, subject, manager)
}

func (s *Service) Resolve(ctx context.Context, in ResolveInput) (*ResolvedTarget, error) {
	target, err := s.store.Get(ctx, s.db.Pool, in.OrgID, in.TargetID)
	if err != nil {
		return nil, err
	}
	if in.Capability != "" && in.Capability != target.Capability() {
		return nil, invalid("capability", "target does not provide the requested capability")
	}
	if in.ExpectedRevision > 0 && in.ExpectedRevision != target.Revision {
		return nil, ErrStaleRevision
	}
	if !target.Enabled {
		return nil, ErrUnavailable
	}
	p, err := s.provider(target.Capability())
	if err != nil {
		return nil, err
	}
	if !actionSupported(p, in.Action) {
		return nil, invalid("action", "provider does not support this action")
	}
	manager, err := s.isManager(ctx, in.OrgID, in.Subject)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, in.OrgID, in.Subject, target.ID, in.Action, manager); err != nil {
		return nil, err
	}
	snapshot, err := s.loadSnapshot(ctx, target)
	if err != nil {
		return nil, err
	}
	descriptor, err := s.describeSnapshot(ctx, target, in.Subject, manager, snapshot)
	if err != nil {
		return nil, err
	}
	if !descriptor.Readiness.State.Selectable() {
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, strings.Join(descriptor.Readiness.Reasons, ","))
	}
	selection, approval, err := p.ValidateSelection(target, in.Selection)
	if err != nil {
		return nil, err
	}
	return &ResolvedTarget{Target: *descriptor, Selection: selection, Approval: approval, Cluster: snapshot.Cluster}, nil
}

func (s *Service) ResolveResource(ctx context.Context, orgID, subject, capability string, action Action, ref TargetResourceRef, selection json.RawMessage) (*ResolvedTarget, error) {
	target, err := s.store.GetByResource(ctx, s.db.Pool, orgID, capability, ref)
	if err != nil {
		return nil, err
	}
	return s.Resolve(ctx, ResolveInput{OrgID: orgID, Subject: subject, TargetID: target.ID, Capability: capability, Action: action, Selection: selection})
}

func (s *Service) loadSnapshot(ctx context.Context, target *Target) (ResourceSnapshot, error) {
	if target.ResourceRef.Kind != ResourceKindCluster {
		return ResourceSnapshot{}, invalid("resourceRef.kind", "only cluster resources are supported")
	}
	if s.sources.Clusters == nil {
		return ResourceSnapshot{}, fmt.Errorf("resourcetargets: cluster source is not configured")
	}
	cluster, err := s.sources.Clusters.GetCluster(ctx, target.ResourceRef.ID)
	if errors.Is(err, clusterregistry.ErrClusterNotFound) {
		return ResourceSnapshot{}, ErrTargetNotFound
	}
	if err != nil {
		return ResourceSnapshot{}, err
	}
	if cluster == nil || cluster.OrgID != target.OrgID {
		return ResourceSnapshot{}, ErrTargetNotFound
	}
	snapshot := ResourceSnapshot{Cluster: cluster}
	if s.sources.Inventory != nil {
		repoID, err := s.sources.Inventory.BaselineRepoSelector(ctx, s.db.Pool, target.OrgID, cluster.ID)
		if err != nil {
			return snapshot, err
		}
		if repoID != "" {
			snapshot.BaselineRepo, err = s.sources.Inventory.GetGitRepo(ctx, s.db.Pool, target.OrgID, repoID)
			if err != nil {
				return snapshot, err
			}
		}
		snapshot.Addons, err = s.sources.Inventory.ListClusterAddons(ctx, s.db.Pool, target.OrgID, cluster.ID)
		if err != nil {
			return snapshot, err
		}
	}
	if s.sources.Capabilities != nil {
		snapshot.Capabilities, err = s.sources.Capabilities.List(ctx, s.db.Pool, cluster.ID)
		if err != nil {
			return snapshot, err
		}
	}
	if s.sources.Teams != nil {
		teams, err := s.sources.Teams.ListTeams(ctx, target.OrgID)
		if err != nil {
			return snapshot, err
		}
		for _, team := range teams {
			snapshot.TeamIDs = append(snapshot.TeamIDs, team.ID)
		}
	}
	return snapshot, nil
}

func (s *Service) recordAudit(ctx context.Context, q db.Querier, orgID, actor, action, objectID string, payload map[string]any) error {
	if s.audit == nil {
		return nil
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ev := &types.AuditEvent{OrgID: orgID, Actor: actor, Impersonator: impersonation.FromContext(ctx),
		Action: action, ObjectType: "resource_target", ObjectID: objectID, Payload: raw}
	if err := impersonation.Stamp(ctx, ev); err != nil {
		return err
	}
	return s.audit.Record(ctx, q, ev)
}
