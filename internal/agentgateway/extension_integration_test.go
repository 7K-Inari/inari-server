//go:build integration

package agentgateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	connect "connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"
	"github.com/7K-Inari/inari-api/gen/go/inari/extensions/v1/extensionsv1connect"

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
		return nil, connect.NewError(connect.CodeUnauthenticated, "unauthenticated")
	}
	ext, ok := f.byToken[raw[len(prefix):]]
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, "unauthenticated")
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
	r.gw.registerSession(cluster.ID, func() {})
	path, handler := r.gw.ExtensionInvokeHandler(auth, 10*time.Second)
	if handler == nil {
		t.Fatal("handler nil with authenticator wired")
	}
	if path != ExtensionInvokeProcedure {
		t.Errorf("path = %q", path)
	}

	mkReq := func(tenantHdr, bearerTok string) (*agentv1.InvokeAction, http.Header) {
		header := http.Header{}
		header.Set(MetadataCluster, cluster.ID)
		header.Set(MetadataTenant, tenantHdr)
		if bearerTok != "" {
			header.Set("Authorization", "Bearer "+bearerTok)
		}
		return &agentv1.InvokeAction{Action: "refresh"}, header
	}

	// Unknown token -> unauthenticated.
	reqBad, hdrBad := mkReq("org:1", "wrong")
	if _, err := r.gw.invokeExtension(ctx, reqBad, hdrBad, auth, time.Second); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("unknown token: err = %v, want unauthenticated", err)
	}
	// Extension invoking in a foreign tenant -> permission denied (org binding).
	reqForeign, hdrForeign := mkReq("org:2", "ext-jwt")
	if _, err := r.gw.invokeExtension(ctx, reqForeign, hdrForeign, auth, time.Second); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("foreign tenant: err = %v, want permission denied", err)
	}

	// Happy path: invoke blocks until the agent acks.
	type result struct {
		resp *agentv1.CommandAck
		err  error
	}
	done := make(chan result, 1)
	go func() {
		reqOK, hdrOK := mkReq("org:1", "ext-jwt")
		resp, err := r.gw.invokeExtension(ctx, reqOK, hdrOK, auth, 10*time.Second)
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
		if res.resp.GetResult() != agentv1.CommandResult_COMMAND_RESULT_APPLIED {
			t.Errorf("result = %v", res.resp.GetResult())
		}
		if res.resp.GetMessage() != "refresh dispatched" {
			t.Errorf("message = %q", res.resp.GetMessage())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("invoke did not return after ack")
	}
}

func TestExtensionInvokeGeneratedHTTPRoundTrip(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	cluster, _ := r.registry.CreateCluster(ctx, "user-1", "org:1", "kind-dev", nil)
	token, _, _ := r.registry.IssueToken(ctx, "user-1", cluster.ID)
	if _, err := r.gw.RegisterCluster(ctx, registerReq(token)); err != nil {
		t.Fatal(err)
	}
	ext := &types.Extension{ID: "extension:1", OrgID: "org:1", Name: "argocd", ClientID: "ext-argocd", State: types.ExtensionStateReady}
	auth := &fakeExtAuth{byToken: map[string]*types.Extension{"ext-jwt": ext}}
	r.gw.registerSession(cluster.ID, func() {})
	path, handler := r.gw.ExtensionInvokeHandler(auth, 10*time.Second)
	if path != extensionsv1connect.AgentGatewayInvokeActionProcedure {
		t.Fatalf("path = %q", path)
	}
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	client := extensionsv1connect.NewAgentGatewayClient(connect.NewClient(connecthttp.NewTransport(ts.Client(), ts.URL)))
	callCtx, info := connect.NewClientContext(ctx)
	info.RequestHeader().Set("Authorization", "Bearer ext-jwt")
	info.RequestHeader().Set(MetadataTenant, "org:1")
	info.RequestHeader().Set(MetadataCluster, cluster.ID)

	type result struct {
		ack *agentv1.CommandAck
		err error
	}
	done := make(chan result, 1)
	go func() {
		ack, err := client.InvokeAction(callCtx, &agentv1.InvokeAction{Action: "refresh"})
		done <- result{ack: ack, err: err}
	}()
	for range 40 {
		due, err := r.gw.Queue().Due(ctx, cluster.ID, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(due) == 1 {
			if err := r.gw.Queue().Complete(ctx, due[0].ID, "acked", "refresh dispatched"); err != nil {
				t.Fatal(err)
			}
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("generated InvokeAction: %v", got.err)
		}
		if got.ack.GetResult() != agentv1.CommandResult_COMMAND_RESULT_APPLIED || got.ack.GetMessage() != "refresh dispatched" {
			t.Fatalf("ack = %+v", got.ack)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("generated InvokeAction did not return")
	}
}

// Disabled without an authenticator.
func TestExtensionInvokeDisabledWithoutAuth(t *testing.T) {
	r := newRig(t, false)
	if _, h := r.gw.ExtensionInvokeHandler(nil, 0); h != nil {
		t.Fatal("expected nil handler with no authenticator")
	}
}

func TestExtensionInvokeDisconnectedFailsBeforeEnqueue(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	cluster, _ := r.registry.CreateCluster(ctx, "user-1", "org:1", "kind-dev", nil)
	token, _, _ := r.registry.IssueToken(ctx, "user-1", cluster.ID)
	if _, err := r.gw.RegisterCluster(ctx, registerReq(token)); err != nil {
		t.Fatal(err)
	}
	ext := &types.Extension{ID: "extension:1", OrgID: "org:1", Name: "argocd", ClientID: "ext-argocd", State: types.ExtensionStateReady}
	auth := &fakeExtAuth{byToken: map[string]*types.Extension{"ext-jwt": ext}}
	header := http.Header{}
	header.Set(MetadataCluster, cluster.ID)
	header.Set(MetadataTenant, "org:1")
	header.Set("Authorization", "Bearer ext-jwt")

	_, err := r.gw.invokeExtension(ctx, &agentv1.InvokeAction{Action: "sync"}, header, auth, 50*time.Millisecond)
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("disconnected invoke err = %v, want UNAVAILABLE", err)
	}
	due, queueErr := r.gw.Queue().Due(ctx, cluster.ID, 10)
	if queueErr != nil {
		t.Fatal(queueErr)
	}
	if len(due) != 0 {
		t.Fatalf("disconnected invoke enqueued %d commands", len(due))
	}
}

func TestExtensionInvokeDisconnectDuringWait(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	cluster, _ := r.registry.CreateCluster(ctx, "user-1", "org:1", "kind-dev", nil)
	token, _, _ := r.registry.IssueToken(ctx, "user-1", cluster.ID)
	if _, err := r.gw.RegisterCluster(ctx, registerReq(token)); err != nil {
		t.Fatal(err)
	}
	ext := &types.Extension{ID: "extension:1", OrgID: "org:1", Name: "argocd", ClientID: "ext-argocd", State: types.ExtensionStateReady}
	auth := &fakeExtAuth{byToken: map[string]*types.Extension{"ext-jwt": ext}}
	header := http.Header{}
	header.Set(MetadataCluster, cluster.ID)
	header.Set(MetadataTenant, "org:1")
	header.Set("Authorization", "Bearer ext-jwt")
	session := r.gw.registerSession(cluster.ID, func() {})

	done := make(chan error, 1)
	go func() {
		_, err := r.gw.invokeExtension(ctx, &agentv1.InvokeAction{Action: "sync"}, header, auth, 100*time.Millisecond)
		done <- err
	}()
	var commandID string
	for range 40 {
		due, err := r.gw.Queue().Due(ctx, cluster.ID, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(due) == 1 {
			commandID = due[0].ID
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if commandID == "" {
		t.Fatal("invoke did not enqueue while connected")
	}
	r.gw.unregisterSession(cluster.ID, session)
	if err := <-done; connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("disconnect during wait err = %v, want UNAVAILABLE", err)
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
	r.gw.registerSession(cluster.ID, func() {})

	mkReq := func(ref string) (*agentv1.InvokeAction, http.Header) {
		header := http.Header{}
		header.Set(MetadataCluster, cluster.ID)
		header.Set(MetadataTenant, "org:1")
		header.Set("Authorization", "Bearer ext-jwt")
		if ref != "" {
			header.Set(MetadataUserCredentialRef, ref)
		}
		return &agentv1.InvokeAction{Action: "sync"}, header
	}

	// JWT-shaped metadata is rejected as a raw-token smuggling attempt.
	reqRaw, hdrRaw := mkReq("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.c2ln")
	if _, err := r.gw.invokeExtension(ctx, reqRaw, hdrRaw, auth, time.Second); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("raw token: err = %v, want invalid argument", err)
	}
	// Self-asserted payload refs are discarded when metadata is absent.
	req, hdr := mkReq("")
	req.UserCredentialRef = "self-asserted"
	if _, err := r.gw.invokeExtension(ctx, req, hdr, auth, 500*time.Millisecond); connect.CodeOf(err) != connect.CodeDeadlineExceeded {
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
		reqOK, hdrOK := mkReq("ucr_01JABCXYZ")
		_, err := r.gw.invokeExtension(ctx, reqOK, hdrOK, auth, 10*time.Second)
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
