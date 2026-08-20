package authz

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/7K-Inari/inari-server/internal/types"
)

// RoleRelation maps a tenancy role to an OpenFGA organization relation.
func RoleRelation(r types.Role) (string, error) {
	switch r {
	case types.RoleOrgAdmin:
		return RelationAdmin, nil
	case types.RolePlatformEngineer:
		return RelationPlatformEngineer, nil
	case types.RoleDeveloper:
		return RelationDeveloper, nil
	case types.RoleViewer:
		return RelationViewer, nil
	}
	return "", fmt.Errorf("authz: unknown role %q", r)
}

// TupleWriter consumes outbox events and syncs OpenFGA tuples.
type TupleWriter struct {
	store Store
}

func NewTupleWriter(s Store) *TupleWriter { return &TupleWriter{store: s} }

func (w *TupleWriter) EventTypes() []string {
	return []string{
		types.EventTenantCreated,
		types.EventTeamCreated,
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
		types.EventTenantZoneActive,
		types.EventTenantZoneClosed,
		types.EventExtensionRegistered,
		types.EventExtensionUnregistered,
		types.EventRolloutCreated,
		types.EventDriftDetected,
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
	case types.EventTeamCreated:
		var p types.TeamCreatedPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		return w.writeOrgRoleTuples(ctx, p.OrgID, []types.TeamSeed{{TeamID: p.TeamID, Name: p.Name, Role: p.Role}}, false)
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
	}
	return nil
}

// writeOrgRoleTuples seeds org role tuples: each team grants its role on the org.
func (w *TupleWriter) writeOrgRoleTuples(ctx context.Context, orgID string, teams []types.TeamSeed, del bool) error {
	var tuples []Tuple
	for _, t := range teams {
		rel, err := RoleRelation(t.Role)
		if err != nil {
			return err
		}
		tuples = append(tuples, Tuple{
			User:     TeamMemberUserset(t.TeamID),
			Relation: rel,
			Object:   OrgObject(orgID),
		})
	}
	if del {
		return w.store.DeleteTuples(ctx, tuples)
	}
	return w.store.WriteTuples(ctx, tuples)
}
