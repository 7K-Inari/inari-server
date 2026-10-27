//go:build integration

package addons

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/7K-Inari/inari-server/internal/impersonation"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// Full PR-merge loop over real Postgres: a PR-policy adopt opens a PR and
// defers registration; when the merge webhook lands (FinalizePRMerge), the
// manifest as committed at the merge SHA is registered and the row flips
// to the merge SHA with pr_url cleared. Redelivery is a no-op.
func TestPRMergeFinalizerIntegration(t *testing.T) {
	database, ctx := setupAddonTest(t)
	e := newEnv(t, database, types.CommitPolicyPullRequest)
	seedClusterRow(t, database, ctx, "c1", "org:1", "prod-eu", map[string]string{"env": "prod"})

	res, err := e.svc.Adopt(ctx, "org:1", "c1", "platform:cert-manager", AdoptInput{
		Version: "v1.16.1",
	}, "user:u1")
	if err != nil {
		t.Fatal(err)
	}
	if res.PRURL == "" {
		t.Fatal("PR policy must open a PR")
	}
	if len(e.queue.cmds) != 0 {
		t.Fatalf("registration must be deferred pre-merge: %+v", e.queue.cmds)
	}

	// The merge lands: the manifest (possibly edited in review) exists at
	// the merge SHA.
	mergeSHA := "mergedeadbeef"
	manifest := e.git.PRs[0].Files[0]
	for _, f := range e.git.PRs[0].Files {
		if strings.HasSuffix(f.Path, "/application.yaml") {
			manifest = f
		}
	}
	if _, err := e.git.CommitFiles(ctx, e.baseline.Repo, mergeSHA,
		[]gitprovider.File{{Path: manifest.Path, Content: manifest.Content}}, "merge PR"); err != nil {
		t.Fatal(err)
	}

	found, err := e.svc.FinalizePRMerge(ctx, "org:1", res.PRURL, mergeSHA)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("found = false, want true")
	}
	if len(e.queue.cmds) != 1 {
		t.Fatalf("registration commands after merge = %d, want 1", len(e.queue.cmds))
	}
	// The bridge command must carry the merged manifest verbatim.
	var cmdAny anypb.Any
	if err := protojson.Unmarshal(e.queue.cmds[0].Payload, &cmdAny); err != nil {
		t.Fatal(err)
	}
	var bridge structpb.Struct
	if err := cmdAny.UnmarshalTo(&bridge); err != nil {
		t.Fatal(err)
	}
	if got := bridge.Fields["manifest"].GetStringValue(); got != string(manifest.Content) {
		t.Errorf("registration manifest does not match the merged file:\n%s", got)
	}
	row, err := e.store.GetClusterAddonByID(ctx, database.Pool, "org:1", res.Addon.ID)
	if err != nil {
		t.Fatal(err)
	}
	if row.CommitSHA != mergeSHA || row.PRURL != "" {
		t.Errorf("row = commit %q pr %q, want %q and empty", row.CommitSHA, row.PRURL, mergeSHA)
	}

	// Webhook redelivery (JetStream at-least-once): idempotent ack.
	found, err = e.svc.FinalizePRMerge(ctx, "org:1", res.PRURL, mergeSHA)
	if err != nil {
		t.Fatal(err)
	}
	if found || len(e.queue.cmds) != 1 {
		t.Errorf("redelivery: found=%v cmds=%d, want false/1", found, len(e.queue.cmds))
	}
}

// A RACING duplicate delivery (two outbox replicas pass FindAddonByPRURL
// before either marks — unlike sequential redelivery, which the pr_url
// guard acks) must not double-audit: the loser's MarkAddonPRMerged applies
// nothing, so its audit entry is skipped and the winner's stands.
func TestPRMergeRacingDuplicateAuditsOnce(t *testing.T) {
	database, ctx := setupAddonTest(t)
	e := newEnv(t, database, types.CommitPolicyPullRequest)
	seedClusterRow(t, database, ctx, "c1", "org:1", "prod-eu", map[string]string{"env": "prod"})

	res, err := e.svc.Adopt(ctx, "org:1", "c1", "platform:cert-manager", AdoptInput{
		Version: "v1.16.1",
	}, "user:u1")
	if err != nil {
		t.Fatal(err)
	}
	// The racing processor fetched its row copy before the winner marked.
	stale, err := e.store.FindAddonByPRURL(ctx, database.Pool, "org:1", res.PRURL)
	if err != nil {
		t.Fatal(err)
	}
	// markPRMerged is called with the impersonated virtual user, as
	// FinalizePRMerge does (audit requires it for system actors).
	finCtx := impersonation.WithImpersonator(ctx, impersonation.VirtualUser("org:1"))
	if _, err := e.svc.markPRMerged(finCtx, "org:1", stale, res.PRURL, "mergedeadbeef"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.markPRMerged(finCtx, "org:1", stale, res.PRURL, "mergedeadbeef"); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := database.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'addon.pr_merged' AND object_id = $1`, stale.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("addon.pr_merged audit rows = %d, want 1 (racing duplicate must not double-audit)", n)
	}
}
