package extensionhost

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	extensionv1 "github.com/7K-Inari/inari-api/contract/extension/v1"
	"github.com/7K-Inari/inari-server/internal/httpserver"
)

func TestMetaContractsNoAuthDeterministicResponse(t *testing.T) {
	policy, err := NewContractPolicy(
		[]string{"inari.plugin.v2", "inari.plugin.v1"},
		[]string{"inari.ui.v2", "inari.ui.v1"},
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	NewMetaHandler(policy, "4.1.0-test").RegisterRoutes(api)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/meta/contracts", nil)
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 without auth or tenant", res.StatusCode)
	}
	if got := res.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	var body extensionv1.ContractMetadata
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.PluginContracts) != 2 || body.PluginContracts[0] != "inari.plugin.v1" || body.PluginContracts[1] != "inari.plugin.v2" {
		t.Fatalf("pluginContracts = %v", body.PluginContracts)
	}
	if len(body.UIHostAPIs) != 2 || body.UIHostAPIs[0] != "inari.ui.v1" || body.UIHostAPIs[1] != "inari.ui.v2" {
		t.Fatalf("uiHostApis = %v", body.UIHostAPIs)
	}
	if body.ServerVersion != "4.1.0-test" {
		t.Fatalf("serverVersion = %q", body.ServerVersion)
	}
}
