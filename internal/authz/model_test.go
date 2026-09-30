package authz

import (
	"testing"

	openfga "github.com/openfga/go-sdk"
)

func typeDef(t *testing.T, name string) openfga.TypeDefinition {
	t.Helper()
	for _, td := range ModelV1().TypeDefinitions {
		if td.Type == name {
			return td
		}
	}
	t.Fatalf("type %s not in ModelV1", name)
	return openfga.TypeDefinition{}
}

func TestModelOrganizationPermissionRelations(t *testing.T) {
	td := typeDef(t, TypeOrganization)
	rels := *td.Relations
	meta := *td.Metadata.Relations
	if len(rels) != len(PermissionCatalog()) {
		t.Fatalf("organization has %d relations, want %d (one per catalog slug)", len(rels), len(PermissionCatalog()))
	}
	for _, p := range PermissionCatalog() {
		rel, _ := PermissionRelation(p.Slug)
		us, ok := rels[rel]
		if !ok {
			t.Fatalf("organization missing relation %s", rel)
		}
		// Direct [team#member] grant only — no hierarchy unions.
		if us.This == nil {
			t.Fatalf("organization.%s must be a direct grant", rel)
		}
		m := meta[rel]
		if m.DirectlyRelatedUserTypes == nil || len(*m.DirectlyRelatedUserTypes) != 1 ||
			(*m.DirectlyRelatedUserTypes)[0].Type != TypeTeam {
			t.Fatalf("organization.%s must be granted [team#member]", rel)
		}
	}
	// The retired hierarchical relations must be gone.
	for _, legacy := range []string{"admin", "platform_engineer", "developer", "viewer"} {
		if _, ok := rels[legacy]; ok {
			t.Fatalf("legacy relation %q still on organization", legacy)
		}
	}
}

func TestModelChildDerivations(t *testing.T) {
	cases := []struct {
		typ, relation, wantRel string
	}{
		{TypeCluster, RelationOperator, RelationClustersRegister},
		{TypeCluster, RelationViewer, RelationTenantRead},
		{TypeCatalogItem, RelationDeployer, RelationCatalogManage},
		{TypeCloudAccount, RelationOperator, RelationCloudAccountsManage},
		{TypePolicyPack, RelationOperator, RelationPoliciesManage},
		{TypeClusterSet, RelationOperator, RelationFleetManage},
		{TypeTenantZone, RelationOperator, RelationZonesManage},
		{TypeRollout, RelationOperator, RelationDeploymentsCreate},
		{TypeExtension, RelationInvoke, RelationExtensionsInvoke},
		{TypeExtension, RelationViewer, RelationTenantRead},
		{TypeDriftEvent, RelationViewer, RelationTenantRead},
	}
	for _, c := range cases {
		td := typeDef(t, c.typ)
		us, ok := (*td.Relations)[c.relation]
		if !ok {
			t.Fatalf("%s missing relation %s", c.typ, c.relation)
		}
		ttu := us.TupleToUserset
		if ttu == nil || ttu.ComputedUserset.Relation == nil || *ttu.ComputedUserset.Relation != c.wantRel {
			t.Fatalf("%s.%s = %+v, want %s from parent", c.typ, c.relation, us, c.wantRel)
		}
	}
	// resource_instance derives through its cluster parent (parent chain
	// unchanged).
	td := typeDef(t, TypeResourceInstance)
	us := (*td.Relations)[RelationEditor]
	if us.TupleToUserset == nil || *us.TupleToUserset.ComputedUserset.Relation != RelationOperator {
		t.Fatalf("resource_instance.editor must stay operator from parent, got %+v", us)
	}
}
