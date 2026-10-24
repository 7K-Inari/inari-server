//go:build integration

package orchestrator_test

import (
	"net/http"
	"testing"
)

// QA probe: repoId "default" is the RepoSelectorDefault sentinel at the
// service layer. With enforcement unwired (this server), it resolves the
// org default. NOTE: with enforcement wired (production), "default" is
// rejected 404 at the enforcement layer because no row has that ID — a
// known inconsistency; clients should send "" for the default.
func TestQADefaultSentinelSelector(t *testing.T) {
	srv, database, git, _, baselineID, _ := itServerWithRepoResolver(t)
	defer srv.Close()

	d := deployInstance(t, srv, deployBody("default"))
	if got := instanceRepoID(t, database, d.InstanceID); got != baselineID {
		t.Errorf("sentinel deploy repo_id = %q, want default %q", got, baselineID)
	}
	if _, ok := git.Files("inari-dev/acme-inari-state", "main")["clusters/cluster-1/postgres-aws/my-db/instance.yaml"]; !ok {
		t.Error("sentinel deploy not committed to default repo")
	}
	if code, body := itReq(t, srv, "POST", "/api/v1/tenants/acme/instances/"+d.InstanceID+"/upgrade", "good",
		`{"toVersion":"1.1.0","repoId":"default"}`); code != http.StatusOK {
		t.Errorf("sentinel upgrade: got %d, want 200 (%s)", code, body)
	}
}
