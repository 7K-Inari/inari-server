//go:build integration

package agentgateway

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"

	"github.com/7K-Inari/inari-server/internal/types"
)

// fakeExtAuth fakes per-extension identity resolution (ADR-0008): tokens
// map to extension rows; unknown tokens are unauthenticated.
type fakeExtAuth struct {
	byToken map[string]*types.Extension
}

func (f *fakeExtAuth) AuthenticateExtension(_ context.Context, header http.Header) (*types.Extension, error) {
	const prefix = "Bearer "
	raw := header.Get("Authorization")
	if len(raw) <= len(prefix) {
		return nil, connect.NewError(connect.CodeUnauthenticated, nil)
	}
	ext, ok := f.byToken[raw[len(prefix):]]
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, nil)
	}
	return ext, nil
}

// The extension-gateway tunnel: InvokeAction enqueues an invoke-action
// command and returns the agent's ack; per-extension identity, org binding,
// and tenant/cluster scoping are enforced.
func TestExtensionInvokeTunnel(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	cluster, _ := r.registry.CreateCluster(ctx, "user-1", "org:1", "kind-dev", nil)
	token, _, _ := r.registry.IssueToken(ctx, "user-1", cluster.ID)
	if _, err := r.gw.RegisterCluster(ctx, registerReq(token)); err != nil {
		t.Fatal(err)
	}

	ext := &types.Extension{
		ID: "extension:1", OrgID: "org:1", Name: "argocd",
		ClientID: "ext-argocd", State: types.ExtensionStateReady,
	}
	auth := &fakeExtAuth{byToken: map[string]*types.Extension{"ext-jwt": ext}}
	path, handler := r.gw.ExtensionInvokeHandler(auth, 10*time.Second)
	if handler == nil {
		t.Fatal("handler nil with authenticator wired")
	}
	if path != ExtensionInvokeProcedure {
		t.Errorf("path = %q", path)
	}

	mkReq := func(tenantHdr, bearerTok string) *connect.Request[agentv1.InvokeAction] {
		req := connect.NewRequest(&agentv1.InvokeAction{Action: "refresh"})
		req.Header().Set(MetadataCluster, cluster.ID)
		req.Header().Set(MetadataTenant, tenantHdr)
		if bearerTok != "" {
			req.Header().Set("Authorization", "Bearer "+bearerTok)
		}
		return req
	}

	// Unknown token -> unauthenticated.
	if _, err := r.gw.invokeExtension(ctx, mkReq("org:1", "wrong"), auth, time.Second); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("unknown token: err = %v, want unauthenticated", err)
	}
	// Extension invoking in a foreign tenant -> permission denied (org binding).
	if _, err := r.gw.invokeExtension(ctx, mkReq("org:2", "ext-jwt"), auth, time.Second); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("foreign tenant: err = %v, want permission denied", err)
	}

	// Happy path: invoke blocks until the agent acks.
	type result struct {
		resp *connect.Response[agentv1.CommandAck]
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := r.gw.invokeExtension(ctx, mkReq("org:1", "ext-jwt"), auth, 10*time.Second)
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
	// Audit attribution: the tunneled action is recorded against the
	// extension's own identity (ADR-0008).
	rows, err := r.db.Pool.Query(ctx,
		`SELECT actor, action FROM audit_events WHERE object_type = 'cluster' AND object_id = $1`, cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	attributed := false
	for rows.Next() {
		var actor, action string
		if err := rows.Scan(&actor, &action); err != nil {
			t.Fatal(err)
		}
		if actor == "ext-argocd" && action == "extension.action_invoked" {
			attributed = true
		}
	}
	if !attributed {
		t.Error("no extension.action_invoked audit row attributed to ext-argocd")
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

// Disabled without an authenticator.
func TestExtensionInvokeDisabledWithoutAuth(t *testing.T) {
	r := newRig(t, false)
	if _, h := r.gw.ExtensionInvokeHandler(nil, 0); h != nil {
		t.Fatal("expected nil handler with no authenticator")
	}
}

// Per-user credential reference (W2 auth model): the hop metadata is the
// only source for InvokeAction.user_credential_ref; the persisted command
// payload carries the opaque reference and never raw token material.
func TestExtensionInvokeUserCredentialRef(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	cluster, _ := r.registry.CreateCluster(ctx, "user-1", "org:1", "kind-dev", nil)
	token, _, _ := r.registry.IssueToken(ctx, "user-1", cluster.ID)
	if _, err := r.gw.RegisterCluster(ctx, registerReq(token)); err != nil {
		t.Fatal(err)
	}
	ext := &types.Extension{
		ID: "extension:1", OrgID: "org:1", Name: "argocd",
		ClientID: "ext-argocd", State: types.ExtensionStateReady,
	}
	auth := &fakeExtAuth{byToken: map[string]*types.Extension{"ext-jwt": ext}}

	mkReq := func(ref string) *connect.Request[agentv1.InvokeAction] {
		req := connect.NewRequest(&agentv1.InvokeAction{Action: "sync"})
		req.Header().Set(MetadataCluster, cluster.ID)
		req.Header().Set(MetadataTenant, "org:1")
		req.Header().Set("Authorization", "Bearer ext-jwt")
		if ref != "" {
			req.Header().Set(MetadataUserCredentialRef, ref)
		}
		return req
	}

	// JWT-shaped metadata is rejected as a raw-token smuggling attempt.
	if _, err := r.gw.invokeExtension(ctx, mkReq("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.c2ln"), auth, time.Second); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("raw token: err = %v, want invalid argument", err)
	}
	// Self-asserted payload refs are discarded when metadata is absent.
	req := mkReq("")
	req.Msg.UserCredentialRef = "self-asserted"
	if _, err := r.gw.invokeExtension(ctx, req, auth, 500*time.Millisecond); connect.CodeOf(err) != connect.CodeDeadlineExceeded {
		t.Fatalf("self-asserted: err = %v, want deadline exceeded (queued without ref)", err)
	}
	// Drain the pending self-asserted command so it cannot shadow the next
	// invoke in Due(), and assert the ref was really stripped.
	due, err := r.gw.Queue().Due(ctx, cluster.ID, 10)
	if err != nil || len(due) == 0 {
		t.Fatalf("drain: %v (%d due)", err, len(due))
	}
	if strings.Contains(string(due[0].Payload), "self-asserted") {
		t.Fatalf("self-asserted ref leaked into payload: %s", due[0].Payload)
	}
	if err := r.gw.Queue().Complete(ctx, due[0].ID, "nacked", "drain"); err != nil {
		t.Fatal(err)
	}

	// Happy path: metadata ref lands in the persisted payload, token-free.
	done := make(chan error, 1)
	go func() {
		_, err := r.gw.invokeExtension(ctx, mkReq("ucr_01JABCXYZ"), auth, 10*time.Second)
		done <- err
	}()
	var payload string
	for i := 0; i < 40; i++ {
		due, err := r.gw.Queue().Due(ctx, cluster.ID, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(due) == 1 && strings.Contains(string(due[0].Payload), "ucr_01JABCXYZ") {
			payload = string(due[0].Payload)
			if err := r.gw.Queue().Complete(ctx, due[0].ID, "acked", "ok"); err != nil {
				t.Fatal(err)
			}
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if payload == "" {
		t.Fatal("no queued command carried the credential ref")
	}
	if strings.Contains(payload, "eyJ") || strings.Contains(payload, "user-token") {
		t.Fatalf("payload carries token material: %s", payload)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("invoke: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("invoke did not return after ack")
	}
}
