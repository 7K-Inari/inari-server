// Tenant-deletion tuple retraction (ADR-0006). TuplesForTenantDeletion is
// shared by the tenancy Deleter's synchronous cleanup step and the
// TupleWriter's defensive tenant.deleting sweep.
package authz

import (
	"fmt"

	"github.com/7K-Inari/inari-server/internal/types"
)

// TuplesForTenantDeletion flattens a TenantDeletingPayload into the exact
// OpenFGA tuple set to retract: org role tuples per team, team member
// tuples, and org parent tuples per child object.
func TuplesForTenantDeletion(p *types.TenantDeletingPayload) ([]Tuple, error) {
	var tuples []Tuple
	for _, t := range p.Teams {
		rel, err := RoleRelation(t.Role)
		if err != nil {
			return nil, err
		}
		tuples = append(tuples, Tuple{
			User: TeamMemberUserset(t.TeamID), Relation: rel, Object: OrgObject(p.OrgID),
		})
	}
	for _, m := range p.Members {
		tuples = append(tuples, Tuple{
			User: UserObject(m.UserID), Relation: RelationMember, Object: TeamObject(m.TeamID),
		})
	}
	for typ, ids := range p.Objects {
		for _, id := range ids {
			obj, err := tenantDeletionObjectString(typ, id)
			if err != nil {
				return nil, err
			}
			tuples = append(tuples, Tuple{
				User: OrgObject(p.OrgID), Relation: RelationParent, Object: obj,
			})
		}
	}
	return tuples, nil
}

func tenantDeletionObjectString(typ, id string) (string, error) {
	switch typ {
	case "cluster":
		return ClusterObject(id), nil
	case "cloud_account":
		return CloudAccountObject(id), nil
	case "cluster_set":
		return ClusterSetObject(id), nil
	case "policy_pack":
		return PolicyPackObject(id), nil
	case "extension":
		return ExtensionObject(id), nil
	case "rollout":
		return RolloutObject(id), nil
	case "drift_event":
		return DriftEventObject(id), nil
	case "tenant_zone":
		return TenantZoneObject(id), nil
	}
	return "", fmt.Errorf("authz: unknown tenant-deletion object type %q", typ)
}
