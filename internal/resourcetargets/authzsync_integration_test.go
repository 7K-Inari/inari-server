//go:build integration

package resourcetargets

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/types"
)

type syncFGA struct{ tuples map[string]authz.Tuple }

func newSyncFGA() *syncFGA                                                     { return &syncFGA{tuples: map[string]authz.Tuple{}} }
func tupleKey(t authz.Tuple) string                                            { return t.User + "|" + t.Relation + "|" + t.Object }
func (f *syncFGA) Check(context.Context, string, string, string) (bool, error) { return false, nil }
func (f *syncFGA) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}
func (f *syncFGA) ReadTuples(_ context.Context, object, relation string) ([]authz.Tuple, error) {
	var out []authz.Tuple
	for _, t := range f.tuples {
		if t.Object == object && t.Relation == relation {
			out = append(out, t)
		}
	}
	return out, nil
}
func (f *syncFGA) WriteTuples(_ context.Context, tuples []authz.Tuple) error {
	for _, t := range tuples {
		f.tuples[tupleKey(t)] = t
	}
	return nil
}
func (f *syncFGA) DeleteTuples(_ context.Context, tuples []authz.Tuple) error {
	for _, t := range tuples {
		delete(f.tuples, tupleKey(t))
	}
	return nil
}
func (f *syncFGA) has(user, relation, object string) bool {
	_, ok := f.tuples[tupleKey(authz.Tuple{User: user, Relation: relation, Object: object})]
	return ok
}

func TestAuthzSyncConvergesCurrentStateAndReplays(t *testing.T) {
	svc, database, _, teamID, _ := serviceFixture(t)
	ctx := context.Background()
	fga := newSyncFGA()
	sync := NewAuthzSync(database, NewStore(), fga)
	target, err := svc.Create(ctx, "org:store", "user:admin", CreateInput{
		Name: "deployment", ResourceRef: ResourceRef{Kind: ResourceKindCluster, ID: "cluster:store"},
		Capability: CapabilityDeploymentCluster,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetGrant(ctx, target.OrgID, target.ID, teamID, ActionUse, "user:admin"); err != nil {
		t.Fatal(err)
	}
	if err := sync.SyncTarget(ctx, target.OrgID, target.ID); err != nil {
		t.Fatal(err)
	}
	object := authz.ResourceTargetObject(target.ID)
	team := authz.TeamMemberUserset(teamID)
	if !fga.has(authz.OrgObject(target.OrgID), authz.RelationParent, object) || !fga.has(team, authz.RelationUseGrant, object) {
		t.Fatalf("missing parent/use tuples: %+v", fga.tuples)
	}
	if _, err := svc.SetGrant(ctx, target.OrgID, target.ID, teamID, ActionView, "user:admin"); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(types.ResourceTargetPayload{OrgID: target.OrgID, TargetID: target.ID})
	if err := sync.Handle(ctx, &types.OutboxEvent{EventType: types.EventResourceTargetGrantChanged, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if fga.has(team, authz.RelationUseGrant, object) || !fga.has(team, authz.RelationViewGrant, object) {
		t.Fatalf("grant downgrade did not converge: %+v", fga.tuples)
	}
	if err := svc.Delete(ctx, target.OrgID, target.ID, "user:admin"); err != nil {
		t.Fatal(err)
	}
	if err := sync.Handle(ctx, &types.OutboxEvent{EventType: types.EventResourceTargetDeleted, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if len(fga.tuples) != 0 {
		t.Fatalf("deleted target left tuples: %+v", fga.tuples)
	}
	// An older create event replayed after deletion must not recreate access.
	if err := sync.Handle(ctx, &types.OutboxEvent{EventType: types.EventResourceTargetCreated, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if len(fga.tuples) != 0 {
		t.Fatalf("stale replay recreated tuples: %+v", fga.tuples)
	}
}
