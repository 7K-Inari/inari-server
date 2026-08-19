package impersonation

import (
	"context"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestVirtualUser(t *testing.T) {
	if got := VirtualUser("org:acme"); got != "user:tenant-acme-automation" {
		t.Fatalf("VirtualUser = %q", got)
	}
	if got := VirtualUser("acme"); got != "user:tenant-acme-automation" {
		t.Fatalf("VirtualUser bare = %q", got)
	}
}

func TestSystemActor(t *testing.T) {
	if got := SystemActor("approvals"); got != "system:approvals" {
		t.Fatalf("SystemActor = %q", got)
	}
}

func TestContextRoundTrip(t *testing.T) {
	ctx := WithImpersonator(context.Background(), VirtualUser("org:acme"))
	if got := FromContext(ctx); got != "user:tenant-acme-automation" {
		t.Fatalf("FromContext = %q", got)
	}
	if got := FromContext(context.Background()); got != "" {
		t.Fatalf("empty context FromContext = %q", got)
	}
}

func TestStampFillsImpersonator(t *testing.T) {
	ctx := WithImpersonator(context.Background(), VirtualUser("org:acme"))
	ev := &types.AuditEvent{OrgID: "org:acme", Actor: SystemActor("approvals"), Action: "deploy.requested"}
	if err := Stamp(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if ev.Impersonator != "user:tenant-acme-automation" {
		t.Fatalf("Impersonator = %q", ev.Impersonator)
	}
	if ev.Actor != "system:approvals" {
		t.Fatalf("Actor = %q", ev.Actor)
	}
}

func TestStampKeepsExplicitImpersonator(t *testing.T) {
	ev := &types.AuditEvent{Actor: "system:x", Impersonator: "user:custom"}
	if err := Stamp(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if ev.Impersonator != "user:custom" {
		t.Fatalf("Impersonator = %q", ev.Impersonator)
	}
}

func TestStampRejectsSameActor(t *testing.T) {
	ev := &types.AuditEvent{Actor: "user:a", Impersonator: "user:a"}
	if err := Stamp(context.Background(), ev); err == nil {
		t.Fatal("expected error when actor == impersonator")
	}
}
