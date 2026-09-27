//go:build integration

package agentgateway

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/types"
)

func testVault(t *testing.T, r *rig) *CredentialVault {
	t.Helper()
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	v, err := NewCredentialVault(r.db, kek)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func enqueueInvokeCommand(t *testing.T, r *rig, clusterID, cmdID string) {
	t.Helper()
	any, err := anypb.New(&agentv1.InvokeAction{CommandId: cmdID, Action: "sync"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := protojson.Marshal(any)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.gw.Queue().Enqueue(context.Background(), &types.AgentCommand{
		ID: cmdID, ClusterID: clusterID,
		Type:    agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_INVOKE_ACTION),
		Payload: raw,
	}); err != nil {
		t.Fatal(err)
	}
}

func countCredentialRows(t *testing.T, r *rig, ref string) int {
	t.Helper()
	var n int
	if err := r.db.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM agent_command_credentials WHERE credential_ref = $1`, ref).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestCredentialVaultMintRedeem(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	cluster, _ := r.registry.CreateCluster(ctx, "user-1", "org:1", "kind-dev", nil)
	v := testVault(t, r)

	enqueueInvokeCommand(t, r, cluster.ID, "cmd-1")
	ref, err := v.Mint(ctx, cluster.ID, "cmd-1", []byte("user-token-abc"), time.Minute)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if !strings.HasPrefix(ref, "cred:") {
		t.Fatalf("ref = %q, want cred: prefix", ref)
	}
	if err := validateUserCredentialRef(ref); err != nil {
		t.Fatalf("minted ref fails the hop validator: %v", err)
	}

	// At rest: no plaintext anywhere in the row.
	var tokenEnc, dekEnc []byte
	if err := r.db.Pool.QueryRow(ctx,
		`SELECT token_enc, dek_enc FROM agent_command_credentials WHERE credential_ref = $1`, ref).
		Scan(&tokenEnc, &dekEnc); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(tokenEnc), "user-token-abc") || strings.Contains(string(dekEnc), "user-token-abc") {
		t.Fatal("plaintext token persisted")
	}

	token, expiresAt, err := v.Redeem(ctx, ref, cluster.ID)
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if string(token) != "user-token-abc" {
		t.Fatalf("token = %q", token)
	}
	if time.Until(expiresAt) > time.Minute || time.Until(expiresAt) < 50*time.Second {
		t.Errorf("expiresAt = %v, want ~1m TTL", time.Until(expiresAt))
	}

	// Single-use: hard-deleted on redeem.
	if n := countCredentialRows(t, r, ref); n != 0 {
		t.Fatalf("row survives redeem: count = %d", n)
	}
	if _, _, err := v.Redeem(ctx, ref, cluster.ID); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("second redeem err = %v, want ErrCredentialNotFound", err)
	}
}

func TestCredentialVaultClusterBinding(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	c1, _ := r.registry.CreateCluster(ctx, "user-1", "org:1", "kind-a", nil)
	c2, _ := r.registry.CreateCluster(ctx, "user-1", "org:1", "kind-b", nil)
	v := testVault(t, r)

	enqueueInvokeCommand(t, r, c1.ID, "cmd-1")
	ref, err := v.Mint(ctx, c1.ID, "cmd-1", []byte("tok"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.Redeem(ctx, ref, c2.ID); !errors.Is(err, ErrCredentialClusterMismatch) {
		t.Fatalf("cross-cluster redeem err = %v, want ErrCredentialClusterMismatch", err)
	}
	// Failed binding check must not burn the credential.
	if n := countCredentialRows(t, r, ref); n != 1 {
		t.Fatalf("cluster-mismatch burned the row: count = %d", n)
	}
}

func TestCredentialVaultExpiredAndMissing(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	cluster, _ := r.registry.CreateCluster(ctx, "user-1", "org:1", "kind-dev", nil)
	v := testVault(t, r)
	v.now = func() time.Time { return time.Now().Add(-time.Hour) } // mint in the past

	enqueueInvokeCommand(t, r, cluster.ID, "cmd-1")
	ref, err := v.Mint(ctx, cluster.ID, "cmd-1", []byte("tok"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	v.now = nil
	if _, _, err := v.Redeem(ctx, ref, cluster.ID); !errors.Is(err, ErrCredentialExpired) {
		t.Fatalf("expired redeem err = %v, want ErrCredentialExpired", err)
	}
	if _, _, err := v.Redeem(ctx, "cred:00000000-0000-0000-0000-000000000000", cluster.ID); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("missing ref err = %v, want ErrCredentialNotFound", err)
	}
}

func TestCredentialVaultSweeper(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	cluster, _ := r.registry.CreateCluster(ctx, "user-1", "org:1", "kind-dev", nil)
	v := testVault(t, r)

	enqueueInvokeCommand(t, r, cluster.ID, "cmd-live")
	liveRef, err := v.Mint(ctx, cluster.ID, "cmd-live", []byte("live"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return time.Now().Add(-time.Hour) }
	enqueueInvokeCommand(t, r, cluster.ID, "cmd-dead")
	deadRef, err := v.Mint(ctx, cluster.ID, "cmd-dead", []byte("dead"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	v.now = nil

	n, err := v.Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if n != 1 {
		t.Fatalf("swept = %d, want 1", n)
	}
	if got := countCredentialRows(t, r, deadRef); got != 0 {
		t.Errorf("expired row survives sweep: %d", got)
	}
	if got := countCredentialRows(t, r, liveRef); got != 1 {
		t.Errorf("live row swept: %d", got)
	}
}

func TestRedeemUserCredentialRPC(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	cluster, _ := r.registry.CreateCluster(ctx, "user-1", "org:1", "kind-dev", nil)
	other, _ := r.registry.CreateCluster(ctx, "user-1", "org:1", "kind-other", nil)
	v := testVault(t, r)
	h := NewCredentialsHandler(v)

	enqueueInvokeCommand(t, r, cluster.ID, "cmd-1")
	ref, err := v.Mint(ctx, cluster.ID, "cmd-1", []byte("user-token-xyz"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	asCluster := func(id string) context.Context {
		return context.WithValue(ctx, agentIdentityKey{}, &authn.Identity{ClusterID: id})
	}

	// Unauthenticated: no cluster identity in context (interceptor would
	// have rejected already; the handler fails closed regardless).
	if _, err := h.RedeemUserCredential(ctx, connect.NewRequest(&agentv1.RedeemUserCredentialRequest{CredentialRef: ref})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("no identity: code = %v, want Unauthenticated", connect.CodeOf(err))
	}

	// Cluster binding comes from the token claim, never the request.
	if _, err := h.RedeemUserCredential(asCluster(other.ID), connect.NewRequest(&agentv1.RedeemUserCredentialRequest{CredentialRef: ref})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("wrong cluster: code = %v, want PermissionDenied", connect.CodeOf(err))
	}

	res, err := h.RedeemUserCredential(asCluster(cluster.ID), connect.NewRequest(&agentv1.RedeemUserCredentialRequest{CredentialRef: ref}))
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if res.Msg.GetBearerToken() != "user-token-xyz" {
		t.Fatalf("bearer = %q", res.Msg.GetBearerToken())
	}
	if res.Msg.GetExpiresAt() == nil {
		t.Error("expires_at not set")
	}

	// Single-use through the RPC surface too.
	if _, err := h.RedeemUserCredential(asCluster(cluster.ID), connect.NewRequest(&agentv1.RedeemUserCredentialRequest{CredentialRef: ref})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("re-redeem: code = %v, want NotFound", connect.CodeOf(err))
	}
}

// No token leakage: across success and every failure path, token material
// never appears in error strings, and never persists in the command journal.
func TestCredentialVaultNoTokenLeakage(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	cluster, _ := r.registry.CreateCluster(ctx, "user-1", "org:1", "kind-dev", nil)
	other, _ := r.registry.CreateCluster(ctx, "user-1", "org:1", "kind-other", nil)
	v := testVault(t, r)
	h := NewCredentialsHandler(v)
	asCluster := func(id string) context.Context {
		return context.WithValue(ctx, agentIdentityKey{}, &authn.Identity{ClusterID: id})
	}
	const secret = "super-secret-user-token"

	enqueueInvokeCommand(t, r, cluster.ID, "cmd-1")
	ref, err := v.Mint(ctx, cluster.ID, "cmd-1", []byte(secret), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	errs := []error{}
	_, _, err = v.Redeem(ctx, ref, other.ID)
	errs = append(errs, err)
	_, _, err = v.Redeem(ctx, "cred:00000000-0000-0000-0000-000000000000", cluster.ID)
	errs = append(errs, err)
	_, err = h.RedeemUserCredential(asCluster(other.ID), connect.NewRequest(&agentv1.RedeemUserCredentialRequest{CredentialRef: ref}))
	errs = append(errs, err)
	res, err := h.RedeemUserCredential(asCluster(cluster.ID), connect.NewRequest(&agentv1.RedeemUserCredentialRequest{CredentialRef: ref}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Msg.GetBearerToken() != secret {
		t.Fatal("redeem returned wrong token")
	}
	_, err = h.RedeemUserCredential(asCluster(cluster.ID), connect.NewRequest(&agentv1.RedeemUserCredentialRequest{CredentialRef: ref}))
	errs = append(errs, err)
	for _, e := range errs {
		if e == nil {
			continue
		}
		if strings.Contains(e.Error(), secret) {
			t.Fatalf("token leaked in error: %v", e)
		}
	}
	var payload string
	if err := r.db.Pool.QueryRow(ctx, `SELECT payload::text FROM agent_commands WHERE id = 'cmd-1'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(payload, secret) {
		t.Fatalf("token persisted in command journal: %s", payload)
	}
}

// the persisted payload carries only the ref, and the token is redeemable.
// InvokeAction with a raw user token over the hop: the vault mints the ref,
// the persisted payload carries only the ref, and the token is redeemable.
func TestExtensionInvokeMintsCredentialRef(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	cluster, _ := r.registry.CreateCluster(ctx, "user-1", "org:1", "kind-dev", nil)
	token, _, _ := r.registry.IssueToken(ctx, "user-1", cluster.ID)
	if _, err := r.gw.RegisterCluster(ctx, registerReq(token)); err != nil {
		t.Fatal(err)
	}
	r.gw.WithCredentialVault(testVault(t, r))
	ext := &types.Extension{
		ID: "extension:1", OrgID: "org:1", Name: "argocd",
		ClientID: "ext-argocd", State: types.ExtensionStateReady,
	}
	auth := &fakeExtAuth{byToken: map[string]*types.Extension{"ext-jwt": ext}}

	mkReq := func() *connect.Request[agentv1.InvokeAction] {
		req := connect.NewRequest(&agentv1.InvokeAction{Action: "sync"})
		req.Header().Set(MetadataCluster, cluster.ID)
		req.Header().Set(MetadataTenant, "org:1")
		req.Header().Set("Authorization", "Bearer ext-jwt")
		return req
	}

	// Raw token + ref header together is ambiguous: rejected.
	both := mkReq()
	both.Header().Set(MetadataUserCredential, "user-token-hop")
	both.Header().Set(MetadataUserCredentialRef, "ucr_01JABCXYZ")
	if _, err := r.gw.invokeExtension(ctx, both, auth, time.Second); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("token+ref: code = %v, want InvalidArgument (%v)", connect.CodeOf(err), err)
	}

	done := make(chan error, 1)
	go func() {
		req := mkReq()
		req.Header().Set(MetadataUserCredential, "user-token-hop")
		_, err := r.gw.invokeExtension(ctx, req, auth, 10*time.Second)
		done <- err
	}()

	var payload, cmdID string
	for i := 0; i < 40; i++ {
		due, err := r.gw.Queue().Due(ctx, cluster.ID, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(due) == 1 {
			payload = string(due[0].Payload)
			cmdID = due[0].ID
			if err := r.gw.Queue().Complete(ctx, cmdID, "acked", "ok"); err != nil {
				t.Fatal(err)
			}
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if payload == "" {
		t.Fatal("invoke command never queued")
	}
	if strings.Contains(payload, "user-token-hop") {
		t.Fatalf("raw token persisted in payload: %s", payload)
	}
	if !strings.Contains(payload, "cred:") {
		t.Fatalf("payload missing minted ref: %s", payload)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("invoke: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("invoke did not return after ack")
	}

	// The minted credential is bound to the command and cluster, and the
	// agent can redeem exactly once.
	var storedRef, storedCmd, storedCluster string
	if err := r.db.Pool.QueryRow(ctx,
		`SELECT credential_ref, command_id, cluster_id FROM agent_command_credentials`).Scan(&storedRef, &storedCmd, &storedCluster); err != nil {
		t.Fatal(err)
	}
	if storedCmd != cmdID || storedCluster != cluster.ID {
		t.Errorf("binding = (%q,%q), want (%q,%q)", storedCmd, storedCluster, cmdID, cluster.ID)
	}
	got, _, err := r.gw.vault.Redeem(ctx, storedRef, cluster.ID)
	if err != nil {
		t.Fatalf("agent redeem: %v", err)
	}
	if string(got) != "user-token-hop" {
		t.Fatalf("redeemed = %q", got)
	}
}

// Raw user token on the hop with no vault wired: fail closed, never store.
func TestExtensionInvokeRawTokenWithoutVaultFailsClosed(t *testing.T) {
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

	req := connect.NewRequest(&agentv1.InvokeAction{Action: "sync"})
	req.Header().Set(MetadataCluster, cluster.ID)
	req.Header().Set(MetadataTenant, "org:1")
	req.Header().Set("Authorization", "Bearer ext-jwt")
	req.Header().Set(MetadataUserCredential, "user-token-hop")
	if _, err := r.gw.invokeExtension(ctx, req, auth, time.Second); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (%v)", connect.CodeOf(err), err)
	}
	due, err := r.gw.Queue().Due(ctx, cluster.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range due {
		if strings.Contains(string(c.Payload), "user-token-hop") {
			t.Fatalf("token persisted: %s", c.Payload)
		}
	}
}
