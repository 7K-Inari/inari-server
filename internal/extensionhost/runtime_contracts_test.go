package extensionhost

import (
	"context"
	"errors"
	"strings"
	"testing"

	extensionv1 "github.com/7K-Inari/inari-api/contract/extension/v1"
	pluginv1 "github.com/7K-Inari/inari-api/gen/go/inari/plugin/v1"
	"github.com/7K-Inari/inari-server/internal/types"
)

func TestVerifyHandshakeWithPolicySkew(t *testing.T) {
	v2 := &pluginv1.PluginInfo{Name: "argocd", Version: "0.1.0", ApiVersion: "inari.plugin.v2"}
	srv := pluginServer(t, v2)
	ext := &types.Extension{Name: "argocd", Version: "0.1.0", Contracts: &extensionv1.Contracts{Backend: []string{"inari.plugin.v1", "inari.plugin.v2"}}}

	_, err := VerifyHandshakeWithPolicy(context.Background(), srv.URL, ext, DefaultContractPolicy())
	var handshakeErr *HandshakeError
	if !errors.As(err, &handshakeErr) || handshakeErr.Reason != string(extensionv1.DegradedContractUnsupported) {
		t.Fatalf("mismatch error = %#v", err)
	}
	if handshakeErr.Actual != "inari.plugin.v2" || !strings.Contains(err.Error(), "inari.plugin.v1") {
		t.Fatalf("mismatch detail = %#v / %v", handshakeErr, err)
	}
	if !errors.Is(err, ErrProtocolVersion) {
		t.Fatalf("error lost ErrProtocolVersion: %v", err)
	}

	policy, err := NewContractPolicy([]string{"inari.plugin.v1", "inari.plugin.v2"}, []string{extensionv1.UIHostAPIV1}, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyHandshakeWithPolicy(context.Background(), srv.URL, ext, policy); err != nil {
		t.Fatalf("v1+v2 server rejected v2 runtime: %v", err)
	}
	ext.Contracts.Backend = []string{"inari.plugin.v1"}
	if _, err := VerifyHandshakeWithPolicy(context.Background(), srv.URL, ext, policy); err == nil {
		t.Fatal("runtime v2 accepted when registration declared only v1")
	}
}
