package secretstores

import (
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"

	"github.com/7K-Inari/inari-server/internal/types"
)

func testStore() *types.SecretStore {
	return &types.SecretStore{
		ID: "secretstore:abc", OrgID: "org:1", Name: "corp-vault", Scope: types.SecretStoreScopeCluster,
		Targets: types.SecretStoreTargets{ClusterIDs: []string{"cluster:1", "cluster:2"}},
		Provider: types.SecretStoreProvider{Vault: &types.VaultProvider{
			Server:        "https://vault.example.com",
			Path:          "secret",
			AuthSecretRef: types.SecretRef{Name: "vault-token", Namespace: "inari-system"},
		}},
	}
}

// The gateway stream only delivers payloads that are protojson of a
// google.protobuf.Any wrapping a known command message; a plain-JSON payload
// is dropped as "bad queued payload" and never reaches an agent.
func decodeAny(t *testing.T, cmd *types.AgentCommand) *anypb.Any {
	t.Helper()
	var any anypb.Any
	if err := protojson.Unmarshal(cmd.Payload, &any); err != nil {
		t.Fatalf("queued payload must be protojson Any: %v\n%s", err, cmd.Payload)
	}
	return &any
}

func TestApplyCommandPayload(t *testing.T) {
	st := testStore()
	cmd, err := applyCommand(st, "cluster:1", 42)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.ID != "secretstore:secretstore:abc:cluster:1:42" {
		t.Fatalf("id = %q", cmd.ID)
	}
	if cmd.ClusterID != "cluster:1" {
		t.Fatalf("cluster = %q", cmd.ClusterID)
	}
	if cmd.Type != agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_SECRET_STORE_APPLY) {
		t.Fatalf("type = %q", cmd.Type)
	}
	anyMsg := decodeAny(t, cmd)
	var m agentv1.SecretStoreApply
	if err := anyMsg.UnmarshalTo(&m); err != nil {
		t.Fatalf("payload must unwrap to SecretStoreApply: %v", err)
	}
	if m.CommandId != cmd.ID || m.Name != "corp-vault" || m.Scope != "cluster" {
		t.Fatalf("message %+v", &m)
	}
	v := m.GetVault()
	if v == nil || v.Server != "https://vault.example.com" || v.Path != "secret" {
		t.Fatalf("vault provider %+v", m.Provider)
	}
	if v.GetAuthSecretRef().GetName() != "vault-token" || v.GetAuthSecretRef().GetNamespace() != "inari-system" {
		t.Fatalf("auth ref %+v", v.AuthSecretRef)
	}
	// No credential material may appear in the payload.
	var raw map[string]any
	if err := json.Unmarshal(cmd.Payload, &raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cmd.Payload), "secret-value") {
		t.Fatal("payload must carry references only")
	}
}

func TestApplyCommandProviderMapping(t *testing.T) {
	cases := []struct {
		name     string
		provider types.SecretStoreProvider
		check    func(*agentv1.SecretStoreApply) bool
	}{
		{"awsSM", types.SecretStoreProvider{AWSSM: &types.AWSSMProvider{Region: "eu-west-1",
			AuthSecretRef: types.SecretRef{Name: "s", Namespace: "n"}}},
			func(m *agentv1.SecretStoreApply) bool { return m.GetAwsSm().GetRegion() == "eu-west-1" }},
		{"gcpsm", types.SecretStoreProvider{GCPSM: &types.GCPSMProvider{ProjectID: "p",
			AuthSecretRef: types.SecretRef{Name: "s", Namespace: "n"}}},
			func(m *agentv1.SecretStoreApply) bool { return m.GetGcpSm().GetProjectId() == "p" }},
		{"azurekv", types.SecretStoreProvider{AzureKV: &types.AzureKVProvider{VaultURL: "https://v", TenantID: "t",
			AuthSecretRef: types.SecretRef{Name: "s", Namespace: "n"}}},
			func(m *agentv1.SecretStoreApply) bool {
				return m.GetAzureKv().GetVaultUrl() == "https://v" && m.GetAzureKv().GetTenantId() == "t"
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := testStore()
			st.Provider = tc.provider
			cmd, err := applyCommand(st, "cluster:1", 1)
			if err != nil {
				t.Fatal(err)
			}
			var m agentv1.SecretStoreApply
			if err := decodeAny(t, cmd).UnmarshalTo(&m); err != nil {
				t.Fatal(err)
			}
			if !tc.check(&m) {
				t.Fatalf("provider mapping wrong: %+v", m.Provider)
			}
		})
	}
}

func TestDeleteCommandPayload(t *testing.T) {
	st := testStore()
	cmd, err := deleteCommand(st, "cluster:2", 7)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Type != agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_SECRET_STORE_DELETE) {
		t.Fatalf("type = %q", cmd.Type)
	}
	var m agentv1.SecretStoreDelete
	if err := decodeAny(t, cmd).UnmarshalTo(&m); err != nil {
		t.Fatal(err)
	}
	if m.CommandId != cmd.ID || m.Name != "corp-vault" || m.Scope != "cluster" {
		t.Fatalf("message %+v", &m)
	}
}

func TestTargetDiff(t *testing.T) {
	removed := targetDiff([]string{"a", "b", "c"}, []string{"b", "d"})
	if len(removed) != 2 || removed[0] != "a" || removed[1] != "c" {
		t.Fatalf("removed = %v", removed)
	}
	if got := targetDiff([]string{"a"}, []string{"a", "b"}); len(got) != 0 {
		t.Fatalf("nothing removed: %v", got)
	}
	if got := targetDiff(nil, []string{"a"}); len(got) != 0 {
		t.Fatalf("empty old: %v", got)
	}
}
