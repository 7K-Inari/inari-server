// Package authz defines the Authorizer interface (fine PEP) plus the OpenFGA
// implementation and the outbox-driven tuple writer. The gateway does coarse
// PEP (internal/authn); module routes call Check/ListObjects via Authorizer.
package authz

import (
	"context"
	"fmt"
	"strings"

	openfga "github.com/openfga/go-sdk"
	"github.com/openfga/go-sdk/client"
)

// Relation names in the OpenFGA model.
const (
	RelationAdmin            = "admin"
	RelationPlatformEngineer = "platform_engineer"
	RelationDeveloper        = "developer"
	RelationViewer           = "viewer"
	RelationMember           = "member"
	RelationParent           = "parent"
	RelationOperator         = "operator"
	RelationDeployer         = "deployer"
	RelationEditor           = "editor"
)

// Object types.
const (
	TypeOrganization     = "organization"
	TypeTeam             = "team"
	TypeCluster          = "cluster"
	TypeCatalogItem      = "catalog_item"
	TypeResourceInstance = "resource_instance"
	TypeCloudAccount     = "cloud_account"
	TypePolicyPack       = "policy_pack"
	TypeClusterSet       = "cluster_set"
)

// Tuple is one relationship fact.
type Tuple struct {
	User     string
	Relation string
	Object   string
}

// Store is the seam over the OpenFGA client (mockable in tests).
type Store interface {
	Check(ctx context.Context, user, relation, object string) (bool, error)
	ListObjects(ctx context.Context, user, relation, objectType string) ([]string, error)
	WriteTuples(ctx context.Context, tuples []Tuple) error
	DeleteTuples(ctx context.Context, tuples []Tuple) error
}

// Authorizer is the module-facing fine-PEP interface.
type Authorizer interface {
	Check(ctx context.Context, user, relation, object string) (bool, error)
	ListObjects(ctx context.Context, user, relation, objectType string) ([]string, error)
}

type fgaAuthorizer struct{ store Store }

// NewAuthorizer wraps a Store as an Authorizer.
func NewAuthorizer(s Store) Authorizer { return &fgaAuthorizer{store: s} }

func (a *fgaAuthorizer) Check(ctx context.Context, user, relation, object string) (bool, error) {
	return a.store.Check(ctx, user, relation, object)
}

func (a *fgaAuthorizer) ListObjects(ctx context.Context, user, relation, objectType string) ([]string, error) {
	return a.store.ListObjects(ctx, user, relation, objectType)
}

// OpenFGAStore implements Store against a running OpenFGA server.
type OpenFGAStore struct {
	client *client.OpenFgaClient
}

// NewOpenFGAStore connects to OpenFGA, ensures the named store exists, and
// writes the v1 authorization model idempotently.
func NewOpenFGAStore(ctx context.Context, apiURL, storeName string) (*OpenFGAStore, error) {
	c, err := client.NewSdkClient(&client.ClientConfiguration{ApiUrl: apiURL})
	if err != nil {
		return nil, fmt.Errorf("authz: sdk client: %w", err)
	}
	s := &OpenFGAStore{client: c}
	if err := s.ensureStore(ctx, storeName); err != nil {
		return nil, err
	}
	if err := s.ensureModel(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *OpenFGAStore) ensureStore(ctx context.Context, name string) error {
	resp, err := s.client.ListStores(ctx).Execute()
	if err != nil {
		return fmt.Errorf("authz: list stores: %w", err)
	}
	for _, st := range resp.Stores {
		if st.Name == name {
			return s.client.SetStoreId(st.Id)
		}
	}
	created, err := s.client.CreateStore(ctx).Body(client.ClientCreateStoreRequest{Name: name}).Execute()
	if err != nil {
		return fmt.Errorf("authz: create store: %w", err)
	}
	return s.client.SetStoreId(created.Id)
}

func (s *OpenFGAStore) ensureModel(ctx context.Context) error {
	resp, err := s.client.WriteAuthorizationModel(ctx).Body(ModelV1()).Execute()
	if err != nil {
		return fmt.Errorf("authz: write model: %w", err)
	}
	return s.client.SetAuthorizationModelId(resp.AuthorizationModelId)
}

func (s *OpenFGAStore) Check(ctx context.Context, user, relation, object string) (bool, error) {
	resp, err := s.client.Check(ctx).Body(client.ClientCheckRequest{
		User: user, Relation: relation, Object: object,
	}).Execute()
	if err != nil {
		return false, fmt.Errorf("authz: check: %w", err)
	}
	allowed := false
	if resp.Allowed != nil {
		allowed = *resp.Allowed
	}
	return allowed, nil
}

func (s *OpenFGAStore) ListObjects(ctx context.Context, user, relation, objectType string) ([]string, error) {
	resp, err := s.client.ListObjects(ctx).Body(client.ClientListObjectsRequest{
		User: user, Relation: relation, Type: objectType,
	}).Execute()
	if err != nil {
		return nil, fmt.Errorf("authz: list objects: %w", err)
	}
	return resp.Objects, nil
}

func (s *OpenFGAStore) WriteTuples(ctx context.Context, tuples []Tuple) error {
	keys := make([]client.ClientTupleKey, 0, len(tuples))
	for _, t := range tuples {
		keys = append(keys, openfga.TupleKey{User: t.User, Relation: t.Relation, Object: t.Object})
	}
	_, err := s.client.Write(ctx).Body(client.ClientWriteRequest{Writes: keys}).Execute()
	if err != nil {
		return fmt.Errorf("authz: write tuples: %w", err)
	}
	return nil
}

func (s *OpenFGAStore) DeleteTuples(ctx context.Context, tuples []Tuple) error {
	keys := make([]client.ClientTupleKeyWithoutCondition, 0, len(tuples))
	for _, t := range tuples {
		keys = append(keys, openfga.TupleKeyWithoutCondition{User: t.User, Relation: t.Relation, Object: t.Object})
	}
	_, err := s.client.Write(ctx).Body(client.ClientWriteRequest{Deletes: keys}).Execute()
	if err != nil {
		return fmt.Errorf("authz: delete tuples: %w", err)
	}
	return nil
}

// ModelV1 is the M0 authorization model: organization roles derive from team
// membership; higher roles imply lower ones. Mirrors model.fga.
func ModelV1() client.ClientWriteAuthorizationModelRequest {
	this := func() *map[string]any { m := map[string]any{}; return &m }
	computed := func(rel string) openfga.Userset {
		return openfga.Userset{ComputedUserset: &openfga.ObjectRelation{Relation: openfga.PtrString(rel)}}
	}
	union := func(children ...openfga.Userset) openfga.Userset {
		return openfga.Userset{Union: &openfga.Usersets{Child: children}}
	}
	teamMemberRef := []openfga.RelationReference{{Type: TypeTeam, Relation: openfga.PtrString(RelationMember)}}
	userRef := []openfga.RelationReference{{Type: "user"}}

	teamRelations := map[string]openfga.Userset{
		RelationMember: openfga.Userset{This: this()},
	}
	direct := func() openfga.Userset { return openfga.Userset{This: this()} }
	orgRelations := map[string]openfga.Userset{
		RelationAdmin:            direct(),
		RelationPlatformEngineer: union(direct(), computed(RelationAdmin)),
		RelationDeveloper:        union(direct(), computed(RelationPlatformEngineer)),
		RelationViewer:           union(direct(), computed(RelationDeveloper)),
	}
	orgMeta := map[string]openfga.RelationMetadata{
		RelationAdmin:            {DirectlyRelatedUserTypes: &teamMemberRef},
		RelationPlatformEngineer: {DirectlyRelatedUserTypes: &teamMemberRef},
		RelationDeveloper:        {DirectlyRelatedUserTypes: &teamMemberRef},
		RelationViewer:           {DirectlyRelatedUserTypes: &teamMemberRef},
	}
	teamMeta := map[string]openfga.RelationMetadata{
		RelationMember: {DirectlyRelatedUserTypes: &userRef},
	}
	orgRef := []openfga.RelationReference{{Type: TypeOrganization}}
	fromParent := func(rel string) openfga.Userset {
		return openfga.Userset{TupleToUserset: &openfga.TupleToUserset{
			Tupleset:        openfga.ObjectRelation{Relation: openfga.PtrString(RelationParent)},
			ComputedUserset: openfga.ObjectRelation{Relation: openfga.PtrString(rel)},
		}}
	}
	clusterRelations := map[string]openfga.Userset{
		RelationParent:   direct(),
		RelationOperator: fromParent(RelationPlatformEngineer),
		RelationViewer:   fromParent(RelationViewer),
	}
	clusterMeta := map[string]openfga.RelationMetadata{
		RelationParent: {DirectlyRelatedUserTypes: &orgRef},
	}
	catalogRelations := map[string]openfga.Userset{
		RelationParent:   direct(),
		RelationDeployer: fromParent(RelationDeveloper),
		RelationViewer:   fromParent(RelationViewer),
	}
	catalogMeta := map[string]openfga.RelationMetadata{
		RelationParent: {DirectlyRelatedUserTypes: &orgRef},
	}
	clusterRef := []openfga.RelationReference{{Type: TypeCluster}}
	instanceRelations := map[string]openfga.Userset{
		RelationParent: direct(),
		RelationEditor: fromParent(RelationOperator),
		RelationViewer: fromParent(RelationViewer),
	}
	instanceMeta := map[string]openfga.RelationMetadata{
		RelationParent: {DirectlyRelatedUserTypes: &clusterRef},
	}
	orgScopedRelations := func() map[string]openfga.Userset {
		return map[string]openfga.Userset{
			RelationParent:   direct(),
			RelationOperator: fromParent(RelationPlatformEngineer),
			RelationViewer:   fromParent(RelationViewer),
		}
	}
	orgScopedMeta := map[string]openfga.RelationMetadata{
		RelationParent: {DirectlyRelatedUserTypes: &orgRef},
	}
	return client.ClientWriteAuthorizationModelRequest{
		SchemaVersion: "1.1",
		TypeDefinitions: []openfga.TypeDefinition{
			{Type: "user"},
			{Type: TypeTeam, Relations: &teamRelations, Metadata: &openfga.Metadata{Relations: &teamMeta}},
			{Type: TypeOrganization, Relations: &orgRelations, Metadata: &openfga.Metadata{Relations: &orgMeta}},
			{Type: TypeCluster, Relations: &clusterRelations, Metadata: &openfga.Metadata{Relations: &clusterMeta}},
			{Type: TypeCatalogItem, Relations: &catalogRelations, Metadata: &openfga.Metadata{Relations: &catalogMeta}},
			{Type: TypeResourceInstance, Relations: &instanceRelations, Metadata: &openfga.Metadata{Relations: &instanceMeta}},
			{Type: TypeCloudAccount, Relations: ptr(orgScopedRelations()), Metadata: &openfga.Metadata{Relations: &orgScopedMeta}},
			{Type: TypePolicyPack, Relations: ptr(orgScopedRelations()), Metadata: &openfga.Metadata{Relations: &orgScopedMeta}},
			{Type: TypeClusterSet, Relations: ptr(orgScopedRelations()), Metadata: &openfga.Metadata{Relations: &orgScopedMeta}},
		},
	}
}

func ptr[T any](v T) *T { return &v }

// Helpers to build fully-qualified FGA object/user strings. OpenFGA object
// IDs may not contain ':' or '#', so the "org:" prefix used by Inari tenant
// IDs (plan §5.2) is stripped here — the mapping must stay consistent for
// both tuple writes and checks.
func OrgObject(orgID string) string {
	return TypeOrganization + ":" + strings.TrimPrefix(orgID, "org:")
}
func TeamObject(teamID string) string       { return TypeTeam + ":" + teamID }
func ClusterObject(clusterID string) string { return TypeCluster + ":" + clusterID }
func UserObject(subject string) string      { return "user:" + subject }
func CatalogItemObject(itemID string) string {
	return TypeCatalogItem + ":" + itemID
}
func ResourceInstanceObject(instanceID string) string {
	return TypeResourceInstance + ":" + instanceID
}
func CloudAccountObject(id string) string { return TypeCloudAccount + ":" + id }
func PolicyPackObject(id string) string   { return TypePolicyPack + ":" + id }
func ClusterSetObject(id string) string   { return TypeClusterSet + ":" + id }
func TeamMemberUserset(teamID string) string {
	return TeamObject(teamID) + "#" + RelationMember
}
