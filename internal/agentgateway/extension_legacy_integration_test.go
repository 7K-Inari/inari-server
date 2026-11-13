//go:build integration

package agentgateway

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"
	"github.com/7K-Inari/inari-server/internal/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// legacyJSONCodec is test-only compatibility coverage for the existing ArgoCD
// client during its migration window. It is not public authoring guidance.
type legacyJSONCodec struct{}

func (legacyJSONCodec) Name() string { return "json" }
func (legacyJSONCodec) Marshal(v any) ([]byte, error) {
	m, ok := v.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("legacy JSON codec: %T is not a proto.Message", v)
	}
	return protojson.Marshal(m)
}
func (legacyJSONCodec) Unmarshal(data []byte, v any) error {
	m, ok := v.(proto.Message)
	if !ok {
		return fmt.Errorf("legacy JSON codec: %T is not a proto.Message", v)
	}
	return protojson.Unmarshal(data, m)
}

func init() { encoding.RegisterCodec(legacyJSONCodec{}) }

func TestExtensionInvokeLegacyProtoJSONGRPCCompatibility(t *testing.T) {
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
	_, handler := r.gw.ExtensionInvokeHandler(auth, 10*time.Second)
	ts := httptest.NewUnstartedServer(handler)
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	ts.Config.Protocols = protocols
	ts.Start()
	t.Cleanup(ts.Close)

	conn, err := grpc.NewClient(ts.Listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	callCtx := metadata.AppendToOutgoingContext(ctx,
		"authorization", "Bearer ext-jwt",
		MetadataTenant, "org:1",
		MetadataCluster, cluster.ID,
	)
	type result struct {
		ack *agentv1.CommandAck
		err error
	}
	done := make(chan result, 1)
	go func() {
		ack := &agentv1.CommandAck{}
		err := conn.Invoke(callCtx, ExtensionInvokeProcedure, &agentv1.InvokeAction{Action: "refresh"}, ack, grpc.CallContentSubtype("json"))
		done <- result{ack: ack, err: err}
	}()
	for range 40 {
		due, err := r.gw.Queue().Due(ctx, cluster.ID, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(due) == 1 {
			if err := r.gw.Queue().Complete(ctx, due[0].ID, "acked", "legacy ack"); err != nil {
				t.Fatal(err)
			}
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("legacy protojson/gRPC InvokeAction: %v", got.err)
		}
		if got.ack.GetResult() != agentv1.CommandResult_COMMAND_RESULT_APPLIED || got.ack.GetMessage() != "legacy ack" {
			t.Fatalf("ack = %+v", got.ack)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("legacy InvokeAction did not return")
	}
}
