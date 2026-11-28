package planlimits

import (
	"context"
	"testing"
)

type projectionStore struct {
	attributes map[string][]string
	writes     int
}

func (s *projectionStore) OrganizationAttributes(context.Context, string) (map[string][]string, error) {
	return s.attributes, nil
}
func (s *projectionStore) UpdateOrganizationAttributes(_ context.Context, _ string, attributes map[string][]string) error {
	s.writes++
	s.attributes = attributes
	return nil
}

func TestKeycloakProjectionWritesOnceAndPreservesAttributes(t *testing.T) {
	store := &projectionStore{attributes: map[string][]string{"unrelated": {"keep"}}}
	projection := NewKeycloakProjection(store, store)
	zero := int64(0)
	limits := Limits{MaxClusters: &zero, FeatureGates: map[string]bool{GateZoneVending: true}}
	if err := projection.PutPlanLimits(context.Background(), "org:kc-1", limits); err != nil {
		t.Fatal(err)
	}
	if store.writes != 1 || store.attributes["unrelated"][0] != "keep" || len(store.attributes[KeycloakPlanLimitsAttribute]) != 1 {
		t.Fatalf("projection = writes %d attributes %+v", store.writes, store.attributes)
	}
	if err := projection.PutPlanLimits(context.Background(), "org:kc-1", limits); err != nil {
		t.Fatal(err)
	}
	if store.writes != 1 {
		t.Fatalf("equal replay caused %d writes", store.writes)
	}
}

func TestKeycloakProjectionRejectsMalformedExistingDocument(t *testing.T) {
	store := &projectionStore{attributes: map[string][]string{KeycloakPlanLimitsAttribute: {"not-json"}}}
	projection := NewKeycloakProjection(store, store)
	if err := projection.PutPlanLimits(context.Background(), "org:kc-1", Limits{AllFeatures: true}); err == nil {
		t.Fatal("malformed existing document was overwritten")
	}
	if store.writes != 0 {
		t.Fatal("malformed document caused a write")
	}
}
