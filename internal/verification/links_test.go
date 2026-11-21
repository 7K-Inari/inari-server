package verification_test

import (
	"testing"
	"time"

	verification "github.com/7K-Inari/inari-server/internal/verification"
)

func TestBuildRunLinks(t *testing.T) {
	now := time.Date(2026, 11, 21, 1, 0, 0, 0, time.UTC)
	expires := now.Add(time.Hour)
	attempt := &verification.RunAttempt{WorkflowName: "vr-1", WorkflowNamespace: "verify", WorkflowUID: "wf-1", LinksExpireAt: &expires}
	links, err := verification.BuildRunLinks("https://argo.example/", attempt, now)
	if err != nil || links == nil {
		t.Fatalf("BuildRunLinks = %#v, %v", links, err)
	}
	if links.Logs != "https://argo.example/workflows/verify/vr-1?tab=logs" || links.Artifacts != "https://argo.example/workflows/verify/vr-1?tab=artifacts" {
		t.Fatalf("unexpected links: %#v", links)
	}
	expired := now.Add(-time.Second)
	attempt.LinksExpireAt = &expired
	if links, err := verification.BuildRunLinks("https://argo.example", attempt, now); err != nil || links != nil {
		t.Fatalf("expired links = %#v, %v", links, err)
	}
	attempt.LinksExpireAt = &expires
	attempt.WorkflowName = "vr-1?tab=attacker"
	if _, err := verification.BuildRunLinks("https://argo.example", attempt, now); err == nil {
		t.Fatal("unsafe Workflow name was accepted")
	}
}
