package secretstores

import (
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func validTargets() types.SecretStoreTargets {
	return types.SecretStoreTargets{ClusterIDs: []string{"cluster:1"}}
}

func validProvider() types.SecretStoreProvider {
	return types.SecretStoreProvider{AWSSM: &types.AWSSMProvider{
		Region:        "eu-west-1",
		AuthSecretRef: types.SecretRef{Name: "aws-creds", Namespace: "external-secrets"},
	}}
}

func TestValidateProviderExactlyOne(t *testing.T) {
	if err := ValidateProvider(types.SecretStoreProvider{}); err == nil {
		t.Fatal("empty provider: want error")
	}
	two := validProvider()
	two.Vault = &types.VaultProvider{Server: "https://vault:8200", AuthSecretRef: types.SecretRef{Name: "v", Namespace: "n"}}
	if err := ValidateProvider(two); err == nil {
		t.Fatal("two providers: want error")
	}
	if err := ValidateProvider(validProvider()); err != nil {
		t.Fatalf("valid awsSM: %v", err)
	}
}

func TestValidateProviderAuthRefRequired(t *testing.T) {
	p := validProvider()
	p.AWSSM.AuthSecretRef.Name = ""
	if err := ValidateProvider(p); err == nil {
		t.Fatal("missing auth secret name: want error")
	}
	p = validProvider()
	p.AWSSM.AuthSecretRef.Namespace = ""
	if err := ValidateProvider(p); err == nil {
		t.Fatal("missing auth secret namespace: want error")
	}
}

func TestValidateProviderRequiredFields(t *testing.T) {
	ref := types.SecretRef{Name: "creds", Namespace: "external-secrets"}
	cases := []struct {
		name     string
		provider types.SecretStoreProvider
		wantErr  bool
	}{
		{"awsSM missing region", types.SecretStoreProvider{AWSSM: &types.AWSSMProvider{AuthSecretRef: ref}}, true},
		{"vault missing server", types.SecretStoreProvider{Vault: &types.VaultProvider{AuthSecretRef: ref}}, true},
		{"gcpsm missing projectId", types.SecretStoreProvider{GCPSM: &types.GCPSMProvider{AuthSecretRef: ref}}, true},
		{"azurekv missing vaultUrl", types.SecretStoreProvider{AzureKV: &types.AzureKVProvider{AuthSecretRef: ref}}, true},
		{"awsSM valid", types.SecretStoreProvider{AWSSM: &types.AWSSMProvider{Region: "eu-west-1", AuthSecretRef: ref}}, false},
		{"vault valid", types.SecretStoreProvider{Vault: &types.VaultProvider{Server: "https://vault:8200", AuthSecretRef: ref}}, false},
		{"gcpsm valid", types.SecretStoreProvider{GCPSM: &types.GCPSMProvider{ProjectID: "proj-1", AuthSecretRef: ref}}, false},
		{"azurekv valid", types.SecretStoreProvider{AzureKV: &types.AzureKVProvider{VaultURL: "https://kv.vault.azure.net", AuthSecretRef: ref}}, false},
	}
	for _, tc := range cases {
		err := ValidateProvider(tc.provider)
		if tc.wantErr && err == nil {
			t.Errorf("%s: want error", tc.name)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func TestValidateTargetsExactlyOne(t *testing.T) {
	if err := ValidateTargets(types.SecretStoreTargets{}); err == nil {
		t.Fatal("empty targets: want error")
	}
	both := types.SecretStoreTargets{ClusterSetRef: "clusterset:1", ClusterIDs: []string{"cluster:1"}}
	if err := ValidateTargets(both); err == nil {
		t.Fatal("both targets: want error")
	}
	if err := ValidateTargets(types.SecretStoreTargets{ClusterSetRef: "clusterset:1"}); err != nil {
		t.Fatalf("clusterSetRef: %v", err)
	}
	if err := ValidateTargets(validTargets()); err != nil {
		t.Fatalf("clusterIds: %v", err)
	}
}

func TestValidateNameAndScope(t *testing.T) {
	for _, name := range []string{"", "Inari-Platform", "bad name", "bad_name", strings.Repeat("a", 64)} {
		if err := ValidateName(name); err == nil {
			t.Errorf("name %q: want error", name)
		}
	}
	if err := ValidateName("inari-platform"); err != nil {
		t.Fatalf("valid name: %v", err)
	}
	if err := ValidateScope("tenant"); err == nil {
		t.Fatal("bad scope: want error")
	}
	if err := ValidateScope(types.SecretStoreScopePlatform); err != nil {
		t.Fatalf("platform scope: %v", err)
	}
	if err := ValidateScope(types.SecretStoreScopeCluster); err != nil {
		t.Fatalf("cluster scope: %v", err)
	}
}
