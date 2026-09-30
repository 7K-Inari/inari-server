package authz

import (
	"context"
	"encoding/json"

	"github.com/7K-Inari/inari-server/internal/types"
)

// permissionTuples flattens (team, permissions) into one org tuple per
// permission slug. Unknown slugs are skipped defensively (the FGA model is
// static; an outbox row written against a retired slug must not stall the
// dispatcher — the OrgRoleSync reconciler converges the difference).
func permissionTuples(orgID, teamID string, permissions []string) []Tuple {
	tuples := make([]Tuple, 0, len(permissions))
	for _, p := range permissions {
		rel, ok := PermissionRelation(p)
		if !ok {
			continue
		}
		tuples = append(tuples, Tuple{
			User:     TeamMemberUserset(teamID),
			Relation: rel,
			Object:   OrgObject(orgID),
		})
	}
	return tuples
}

// TupleWriter consumes outbox events and syncs OpenFGA tuples.
type TupleWriter struct {
	store Store
}

func NewTupleWriter(s Store) *TupleWriter { return &TupleWriter{store: s} }

func (w *TupleWriter) EventTypes() []string {
	return []string{
		types.EventTenantCreated,
		types.EventTenantDeleting,
		types.EventTenantRestored,
		types.EventTeamCreated,
		types.EventTeamDeleted,
		types.EventMembershipAdded,
		types.EventMembershipRemoved,
		types.EventClusterCreated,
		types.EventClusterRevoked,
		types.EventCatalogItemUpserted,
		types.EventDeployRequested,
		types.EventInstanceCreated,
		types.EventCloudAccountRegistered,
		types.EventCloudAccountDeregistered,
		types.EventClusterSetCreated,
		types.EventClusterSetDeleted,
		types.EventPolicyPackAssigned,
		types.EventPolicyPackUnassigned,
		types.EventPolicyPackDeleted,
		types.EventTenantZoneActive,
		types.EventTenantZoneClosed,
		types.EventExtensionRegistered,
		types.EventExtensionUnregistered,
		types.EventRolloutCreated,
		types.EventDriftDetected,
		types.EventRBACMappingsUpdated,
		types.EventRoleCreated,
		types.EventRoleUpdated,
		types.EventRoleDeleted,
	}
}

func (w *TupleWriter) Handle(ctx context.Context, ev *types.OutboxEvent) error {
	switch ev.EventType {
	case types.EventTenantCreated:
		var p types.TenantCreatedPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		return w.writeOrgRoleTuples(ctx, p.OrgID, p.Teams, false)
	case types.EventTenantDeleting:
		// Defensive sweep (ADR-0006): the Deleter retracts these tuples
		// synchronously; this catches any drift between the snapshot and
		// the live store. Deletes of absent tuples are no-ops.
		var p types.TenantDeletingPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		tuples, err := TuplesForTenantDeletion(&p)
		if err != nil {
			return err
		}
		if len(tuples) == 0 {
			return nil
		}
		return w.store.DeleteTuples(ctx, tuples)
	case types.EventTenantRestored:
		// Decommission denied or cancelled: re-seed the tuples swept at
		// freeze time from the same snapshot (writes are idempotent).
		var p types.TenantDeletingPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		tuples, err := TuplesForTenantDeletion(&p)
		if err != nil {
			return err
		}
		if len(tuples) == 0 {
			return nil
		}
		return w.store.WriteTuples(ctx, tuples)
	case types.EventTeamCreated:
		var p types.TeamCreatedPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		return w.store.WriteTuples(ctx, permissionTuples(p.OrgID, p.TeamID, p.Permissions))
	case types.EventTeamDeleted:
		var p types.TeamCreatedPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		// Removes the team#member → permission org tuples. Per-member
		// team:<id>#member tuples dangle harmlessly once the team object is
		// gone.
		return w.store.DeleteTuples(ctx, permissionTuples(p.OrgID, p.TeamID, p.Permissions))
	case types.EventMembershipAdded:
		var p types.MembershipPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		return w.store.WriteTuples(ctx, []Tuple{{
			User: UserObject(p.UserID), Relation: RelationMember, Object: TeamObject(p.TeamID),
		}})
	case types.EventMembershipRemoved:
		var p types.MembershipPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		return w.store.DeleteTuples(ctx, []Tuple{{
			User: UserObject(p.UserID), Relation: RelationMember, Object: TeamObject(p.TeamID),
		}})
	case types.EventClusterCreated:
		var p types.ClusterPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		return w.store.WriteTuples(ctx, []Tuple{{
			User: OrgObject(p.OrgID), Relation: RelationParent, Object: ClusterObject(p.ClusterID),
		}})
	case types.EventClusterRevoked:
		var p types.ClusterPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		return w.store.DeleteTuples(ctx, []Tuple{{
			User: OrgObject(p.OrgID), Relation: RelationParent, Object: ClusterObject(p.ClusterID),
		}})
	case types.EventCatalogItemUpserted:
		var p types.CatalogItemPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		if p.OrgID == "" {
			return nil // global curated/platform items are public to all orgs
		}
		return w.store.WriteTuples(ctx, []Tuple{{
			User: OrgObject(p.OrgID), Relation: RelationParent, Object: CatalogItemObject(p.ItemID),
		}})
	case types.EventDeployRequested, types.EventInstanceCreated:
		var p types.DeployRequestedPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		return w.store.WriteTuples(ctx, []Tuple{{
			User: ClusterObject(p.ClusterID), Relation: RelationParent, Object: ResourceInstanceObject(p.InstanceID),
		}})
	case types.EventCloudAccountRegistered:
		var p types.CloudAccountPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		return w.store.WriteTuples(ctx, []Tuple{{
			User: OrgObject(p.OrgID), Relation: RelationParent, Object: CloudAccountObject(p.AccountID),
		}})
	case types.EventTenantZoneActive:
		// The zone joins the hierarchy under its own (wired) organization.
		var p types.TenantZonePayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		if p.ZoneOrgID == "" {
			return nil
		}
		return w.store.WriteTuples(ctx, []Tuple{{
			User: OrgObject(p.ZoneOrgID), Relation: RelationParent, Object: TenantZoneObject(p.ZoneID),
		}})
	case types.EventTenantZoneClosed:
		var p types.TenantZonePayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		if p.ZoneOrgID == "" {
			return nil
		}
		return w.store.DeleteTuples(ctx, []Tuple{{
			User: OrgObject(p.ZoneOrgID), Relation: RelationParent, Object: TenantZoneObject(p.ZoneID),
		}})
	case types.EventCloudAccountDeregistered:
		var p types.CloudAccountPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		return w.store.DeleteTuples(ctx, []Tuple{{
			User: OrgObject(p.OrgID), Relation: RelationParent, Object: CloudAccountObject(p.AccountID),
		}})
	case types.EventClusterSetCreated:
		var p types.ClusterSetPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		return w.store.WriteTuples(ctx, []Tuple{{
			User: OrgObject(p.OrgID), Relation: RelationParent, Object: ClusterSetObject(p.ClusterSetID),
		}})
	case types.EventClusterSetDeleted:
		var p types.ClusterSetPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		return w.store.DeleteTuples(ctx, []Tuple{{
			User: OrgObject(p.OrgID), Relation: RelationParent, Object: ClusterSetObject(p.ClusterSetID),
		}})
	case types.EventPolicyPackAssigned:
		var p types.PolicyPackAssignedPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		return w.store.WriteTuples(ctx, []Tuple{{
			User: OrgObject(p.OrgID), Relation: RelationParent, Object: PolicyPackObject(p.PackID),
		}})
	case types.EventPolicyPackUnassigned, types.EventPolicyPackDeleted:
		// Retract the pack's parent tuple (mirrors EventClusterSetDeleted).
		// policy_pack.unassigned is only emitted by the force-delete cascade,
		// where the pack row is deleted in the same TX, so retraction is safe.
		var p types.PolicyPackAssignedPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		return w.store.DeleteTuples(ctx, []Tuple{{
			User: OrgObject(p.OrgID), Relation: RelationParent, Object: PolicyPackObject(p.PackID),
		}})
	case types.EventExtensionRegistered:
		var p types.ExtensionPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		if p.OrgID == "" {
			return nil // platform-global extensions: invoke is granted per-org later
		}
		return w.store.WriteTuples(ctx, []Tuple{{
			User: OrgObject(p.OrgID), Relation: RelationParent, Object: ExtensionObject(p.ExtensionID),
		}})
	case types.EventExtensionUnregistered:
		var p types.ExtensionPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		if p.OrgID == "" {
			return nil
		}
		return w.store.DeleteTuples(ctx, []Tuple{{
			User: OrgObject(p.OrgID), Relation: RelationParent, Object: ExtensionObject(p.ExtensionID),
		}})
	case types.EventRolloutCreated:
		var p types.RolloutPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		return w.store.WriteTuples(ctx, []Tuple{{
			User: OrgObject(p.OrgID), Relation: RelationParent, Object: RolloutObject(p.RolloutID),
		}})
	case types.EventDriftDetected:
		var p types.DriftPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		return w.store.WriteTuples(ctx, []Tuple{{
			User: OrgObject(p.OrgID), Relation: RelationParent, Object: DriftEventObject(p.DriftID),
		}})
	case types.EventRBACMappingsUpdated:
		var p types.RBACMappingsPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		var del, add []Tuple
		for _, c := range p.Changes {
			del = append(del, permissionTuples(p.OrgID, c.TeamID, c.OldPermissions)...)
			add = append(add, permissionTuples(p.OrgID, c.TeamID, c.NewPermissions)...)
		}
		if len(del) > 0 {
			if err := w.store.DeleteTuples(ctx, del); err != nil {
				return err
			}
		}
		if len(add) > 0 {
			return w.store.WriteTuples(ctx, add)
		}
	case types.EventRoleCreated:
		// A fresh role has no bound teams, so no tuples to write; the event
		// exists for audit/rbacmaterialize.
		return nil
	case types.EventRoleUpdated:
		// Permission bundle changed: rewrite the org tuples of every team
		// bound to the role from the payload snapshots.
		var p types.RolePayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		var del, add []Tuple
		for _, teamID := range p.TeamIDs {
			del = append(del, permissionTuples(p.OrgID, teamID, p.OldPermissions)...)
			add = append(add, permissionTuples(p.OrgID, teamID, p.NewPermissions)...)
		}
		if len(del) > 0 {
			if err := w.store.DeleteTuples(ctx, del); err != nil {
				return err
			}
		}
		if len(add) > 0 {
			return w.store.WriteTuples(ctx, add)
		}
	case types.EventRoleDeleted:
		// Deleting a role with bound teams is rejected, so there is nothing
		// to retract; retract defensively if TeamIDs ever arrives non-empty.
		var p types.RolePayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		var del []Tuple
		for _, teamID := range p.TeamIDs {
			del = append(del, permissionTuples(p.OrgID, teamID, p.OldPermissions)...)
		}
		if len(del) > 0 {
			return w.store.DeleteTuples(ctx, del)
		}
	}
	return nil
}

// writeOrgRoleTuples seeds org permission tuples: each team grants one
// tuple per permission in its role's bundle.
func (w *TupleWriter) writeOrgRoleTuples(ctx context.Context, orgID string, teams []types.TeamSeed, del bool) error {
	var tuples []Tuple
	for _, t := range teams {
		tuples = append(tuples, permissionTuples(orgID, t.TeamID, t.Permissions)...)
	}
	if len(tuples) == 0 {
		return nil
	}
	if del {
		return w.store.DeleteTuples(ctx, tuples)
	}
	return w.store.WriteTuples(ctx, tuples)
}
