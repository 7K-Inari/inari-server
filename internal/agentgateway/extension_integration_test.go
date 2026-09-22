//go:build integration

package agentgateway

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"
)

// The extension-gateway tunnel: InvokeAction enqueues an invoke-action
// command and returns the agent's ack; auth gate and tenant/cluster scoping
// are enforced.
func TestExtensionInvokeTunnel(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	cluster, _ := r.registry.CreateCluster(ctx, "user-1", "org:1", "kind-dev", nil)
	token, _, _ := r.registry.IssueToken(ctx, "user-1", cluster.ID)
	if _, err := r.gw.RegisterCluster(ctx, registerReq(token)); err != nil {
		t.Fatal(err)
	}

	const gate = "gate-token"
	path, handler := r.gw.ExtensionInvokeHandler(gate, 10*time.Second)
	if handler == nil {
		t.Fatal("handler nil with token set")
	}
	if path != ExtensionInvokeProcedure {
		t.Errorf("path = %q", path)
	}

	mkReq := func(tenantHdr, tokenHdr string) *connect.Request[agentv1.InvokeAction] {
		req := connect.NewRequest(&agentv1.InvokeAction{Action: "refresh"})
		req.Header().Set(MetadataCluster, cluster.ID)
		req.Header().Set(MetadataTenant, tenantHdr)
		if tokenHdr != "" {
			req.Header().Set(headerExtToken, tokenHdr)
		}
		return req
	}

	// Wrong token -> unauthenticated.
	if _, err := r.gw.invokeExtension(ctx, mkReq("org:1", "wrong"), gate, time.Second); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("wrong token: err = %v, want unauthenticated", err)
	}
	// Cluster of another tenant -> permission denied.
	if _, err := r.gw.invokeExtension(ctx, mkReq("org:2", gate), gate, time.Second); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("foreign tenant: err = %v, want permission denied", err)
	}

	// Happy path: invoke blocks until the agent acks.
	type result struct {
		resp *connect.Response[agentv1.CommandAck]
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := r.gw.invokeExtension(ctx, mkReq("org:1", gate), gate, 10*time.Second)
		done <- result{resp, err}
	}()

	var cmdID string
	for i := 0; i < 40; i++ {
		due, err := r.gw.Queue().Due(ctx, cluster.ID, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(due) == 1 {
			cmdID = due[0].ID
			if due[0].Type != agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_INVOKE_ACTION) {
				t.Errorf("command type = %q", due[0].Type)
			}
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if cmdID == "" {
		t.Fatal("invoke command never queued")
	}
	if err := r.gw.Queue().Complete(ctx, cmdID, "acked", "refresh dispatched"); err != nil {
		t.Fatal(err)
	}
	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("invoke: %v", res.err)
		}
		if res.resp.Msg.GetResult() != agentv1.CommandResult_COMMAND_RESULT_APPLIED {
			t.Errorf("result = %v", res.resp.Msg.GetResult())
		}
		if res.resp.Msg.GetMessage() != "refresh dispatched" {
			t.Errorf("message = %q", res.resp.Msg.GetMessage())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("invoke did not return after ack")
	}
}

// Disabled without a gate token.
func TestExtensionInvokeDisabledWithoutToken(t *testing.T) {
	r := newRig(t, false)
	if _, h := r.gw.ExtensionInvokeHandler("", 0); h != nil {
		t.Fatal("expected nil handler with empty token")
	}
}
