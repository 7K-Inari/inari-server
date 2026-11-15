//go:build integration

package extensionhost_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	extensionv1 "github.com/7K-Inari/inari-api/contract/extension/v1"
	pluginv1 "github.com/7K-Inari/inari-api/gen/go/inari/plugin/v1"
	"github.com/7K-Inari/inari-api/gen/go/inari/plugin/v1/pluginv1connect"
	"github.com/7K-Inari/inari-server/internal/extensionhost"
	"github.com/7K-Inari/inari-server/internal/types"
)

type contractPlugin struct{ info *pluginv1.PluginInfo }

func (p *contractPlugin) GetInfo(context.Context, *pluginv1.GetInfoRequest) (*pluginv1.GetInfoResponse, error) {
	return &pluginv1.GetInfoResponse{Info: p.info}, nil
}
func (p *contractPlugin) GetCapabilities(context.Context, *pluginv1.GetCapabilitiesRequest) (*pluginv1.GetCapabilitiesResponse, error) {
	return &pluginv1.GetCapabilitiesResponse{}, nil
}
func (p *contractPlugin) Invoke(context.Context, *pluginv1.InvokeRequest) (*pluginv1.InvokeResponse, error) {
	return &pluginv1.InvokeResponse{}, nil
}
func (p *contractPlugin) HealthCheck(context.Context, *pluginv1.HealthCheckRequest) (*pluginv1.HealthCheckResponse, error) {
	return &pluginv1.HealthCheckResponse{Status: pluginv1.HealthCheckResponse_SERVING_STATUS_SERVING}, nil
}

func contractPluginServer(t *testing.T, info *pluginv1.PluginInfo) *httptest.Server {
	t.Helper()
	server := connect.NewServer()
	pluginv1connect.RegisterPluginContractServiceHandler(server, &contractPlugin{info: info})
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestVerifyPersistsTypedDegradedReasonAndClearsOnRecovery(t *testing.T) {
	svc := itService(t)
	ctx := context.Background()
	info := &pluginv1.PluginInfo{Name: "paired", Version: "1.0.0", ApiVersion: "inari.plugin.v1"}
	srv := contractPluginServer(t, info)
	e, _, err := svc.Register(ctx, "user-1", extensionhost.RegisterInput{
		OrgID: "org:1", Name: "paired", Version: "1.0.0", Endpoint: srv.URL,
		Manifest: json.RawMessage(`{"contracts":{"backend":["inari.plugin.v1","inari.plugin.v2"]}}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(ctx, "user-1", "org:1", e.ID); err != nil {
		t.Fatalf("initial verify: %v", err)
	}

	info.ApiVersion = "inari.plugin.v2"
	if _, err := svc.Verify(ctx, "user-1", "org:1", e.ID); err == nil {
		t.Fatal("unsupported runtime was accepted")
	}
	got, err := svc.Get(ctx, "org:1", e.ID)
	if err != nil || got.State != types.ExtensionStateDegraded || got.DegradedReason != string(extensionv1.DegradedContractUnsupported) {
		t.Fatalf("degraded projection = %+v, %v", got, err)
	}
	if got.DegradedDetail == "" {
		t.Fatal("degraded detail is empty")
	}

	info.ApiVersion = "inari.plugin.v1"
	info.Name = "evil"
	if _, err := svc.Verify(ctx, "user-1", "org:1", e.ID); err == nil {
		t.Fatal("identity mismatch was accepted")
	}
	got, _ = svc.Get(ctx, "org:1", e.ID)
	if got.DegradedReason != string(extensionv1.DegradedIdentityMismatch) {
		t.Fatalf("identity mismatch left stale contract reason: %+v", got)
	}

	info.Name = "paired"
	info.ApiVersion = "inari.plugin.v1"
	if _, err := svc.Verify(ctx, "user-1", "org:1", e.ID); err != nil {
		t.Fatalf("recovery verify: %v", err)
	}
	got, _ = svc.Get(ctx, "org:1", e.ID)
	if got.State != types.ExtensionStateReady || got.DegradedReason != "" || got.DegradedDetail != "" {
		t.Fatalf("recovery did not clear degraded metadata: %+v", got)
	}
}
