//go:build integration

package authz

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/testutil"
)

func TestResourceTargetModelAgainstOpenFGA(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	endpoint, err := testutil.SharedOpenFGA(ctx)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		endpoint = "http://" + endpoint
	}
	store, err := NewOpenFGAStore(ctx, endpoint, "resource-target-model-integration")
	if err != nil {
		t.Fatalf("bootstrap real OpenFGA model: %v", err)
	}

	const (
		orgID     = "org:acme"
		teamDev   = "team-dev"
		teamAdmin = "team-admin"
		deploy    = "rt-deploy"
		grafana   = "rt-grafana"
		viewOnly  = "rt-view"
		managed   = "rt-managed"
	)
	org := OrgObject(orgID)
	devMembers := TeamMemberUserset(teamDev)
	adminMembers := TeamMemberUserset(teamAdmin)
	tuples := []Tuple{
		{User: UserObject("alice"), Relation: RelationMember, Object: TeamObject(teamDev)},
		{User: UserObject("manager"), Relation: RelationMember, Object: TeamObject(teamAdmin)},
		{User: adminMembers, Relation: RelationResourceTargetsManage, Object: org},
		{User: devMembers, Relation: RelationUseGrant, Object: ResourceTargetObject(deploy)},
		{User: devMembers, Relation: RelationProvisionGrant, Object: ResourceTargetObject(grafana)},
		{User: devMembers, Relation: RelationViewGrant, Object: ResourceTargetObject(viewOnly)},
	}
	for _, targetID := range []string{deploy, grafana, viewOnly, managed} {
		tuples = append(tuples, Tuple{User: org, Relation: RelationParent, Object: ResourceTargetObject(targetID)})
	}
	if err := store.WriteTuples(ctx, tuples); err != nil {
		t.Fatalf("write target grants: %v", err)
	}

	check := func(user, relation, targetID string, want bool) {
		t.Helper()
		got, err := store.Check(ctx, UserObject(user), relation, ResourceTargetObject(targetID))
		if err != nil {
			t.Fatalf("Check %s#%s@%s: %v", relation, user, targetID, err)
		}
		if got != want {
			t.Errorf("Check %s#%s@%s = %t, want %t", relation, user, targetID, got, want)
		}
	}
	for _, tc := range []struct {
		user, relation, target string
		want                   bool
	}{
		{"alice", RelationViewer, deploy, true},
		{"alice", RelationUse, deploy, true},
		{"alice", RelationProvision, deploy, false},
		{"alice", RelationViewer, grafana, true},
		{"alice", RelationProvision, grafana, true},
		{"alice", RelationUse, grafana, false},
		{"alice", RelationViewer, viewOnly, true},
		{"alice", RelationUse, viewOnly, false},
		{"alice", RelationProvision, viewOnly, false},
		{"alice", RelationViewer, managed, false},
		{"manager", RelationViewer, managed, true},
		{"manager", RelationUse, managed, true},
		{"manager", RelationProvision, managed, true},
		{"manager", RelationViewer, deploy, true},
		{"manager", RelationUse, deploy, true},
		{"manager", RelationProvision, deploy, true},
		{"outsider", RelationViewer, viewOnly, false},
	} {
		check(tc.user, tc.relation, tc.target, tc.want)
	}

	assertObjects := func(user, relation string, want []string) {
		t.Helper()
		got, err := store.ListObjects(ctx, UserObject(user), relation, TypeResourceTarget)
		if err != nil {
			t.Fatalf("ListObjects %s#%s: %v", relation, user, err)
		}
		for i, object := range want {
			want[i] = ResourceTargetObject(object)
		}
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("ListObjects %s#%s = %v, want %v", relation, user, got, want)
		}
	}
	assertObjects("alice", RelationViewer, []string{deploy, grafana, viewOnly})
	assertObjects("alice", RelationUse, []string{deploy})
	assertObjects("alice", RelationProvision, []string{grafana})
	assertObjects("manager", RelationViewer, []string{deploy, grafana, viewOnly, managed})
	assertObjects("manager", RelationUse, []string{deploy, grafana, viewOnly, managed})
	assertObjects("manager", RelationProvision, []string{deploy, grafana, viewOnly, managed})
	assertObjects("outsider", RelationViewer, nil)

	// Team expansion is live: removing the member tuple retracts every grant
	// reached through team#member without rewriting the target tuples.
	if err := store.DeleteTuples(ctx, []Tuple{{User: UserObject("alice"), Relation: RelationMember, Object: TeamObject(teamDev)}}); err != nil {
		t.Fatal(err)
	}
	check("alice", RelationViewer, viewOnly, false)
	check("alice", RelationUse, deploy, false)
	check("alice", RelationProvision, grafana, false)
	assertObjects("alice", RelationViewer, nil)
	if err := store.WriteTuples(ctx, []Tuple{{User: UserObject("alice"), Relation: RelationMember, Object: TeamObject(teamDev)}}); err != nil {
		t.Fatal(err)
	}
	check("alice", RelationViewer, viewOnly, true)

	// Direct-grant revocation also removes viewer through the union and is
	// reflected by ListObjects, not only by an individual Check.
	if err := store.DeleteTuples(ctx, []Tuple{
		{User: devMembers, Relation: RelationUseGrant, Object: ResourceTargetObject(deploy)},
		{User: devMembers, Relation: RelationProvisionGrant, Object: ResourceTargetObject(grafana)},
		{User: devMembers, Relation: RelationViewGrant, Object: ResourceTargetObject(viewOnly)},
	}); err != nil {
		t.Fatal(err)
	}
	check("alice", RelationUse, deploy, false)
	check("alice", RelationViewer, deploy, false)
	check("alice", RelationProvision, grafana, false)
	check("alice", RelationViewer, grafana, false)
	check("alice", RelationViewer, viewOnly, false)
	assertObjects("alice", RelationViewer, nil)
	assertObjects("alice", RelationUse, nil)
	assertObjects("alice", RelationProvision, nil)

	// Manager access derives through parent -> organization permission and is
	// revoked by deleting that org tuple, independently of direct team grants.
	if err := store.DeleteTuples(ctx, []Tuple{{User: adminMembers, Relation: RelationResourceTargetsManage, Object: org}}); err != nil {
		t.Fatal(err)
	}
	check("manager", RelationViewer, managed, false)
	check("manager", RelationUse, managed, false)
	check("manager", RelationProvision, managed, false)
	assertObjects("manager", RelationViewer, nil)
}
