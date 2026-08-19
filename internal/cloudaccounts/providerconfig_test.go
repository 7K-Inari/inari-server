package cloudaccounts

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/7K-Inari/inari-server/internal/types"
)

func renderToMap(t *testing.T, acct *types.CloudAccount, cluster *types.Cluster) map[string]any {
	t.Helper()
	raw, err := RenderProviderConfig(acct, cluster)
	if err != nil {
		t.Fatalf("RenderProviderConfig: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("rendered YAML does not parse: %v\n%s", err, raw)
	}
	return doc
}

func nested(m map[string]any, path ...string) any {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[p]
	}
	return cur
}

func testAccount() *types.CloudAccount {
	return &types.CloudAccount{
		ID:         "cloudaccount:1",
		OrgID:      "org:1",
		Provider:   "aws",
		AccountID:  "123456789012",
		RoleARN:    "arn:aws:iam::123456789012:role/inari-crossplane",
		ExternalID: "ext-abc",
		RunContext: types.CloudAccountRunContextTenant,
		State:      types.CloudAccountStateActive,
	}
}

func TestRenderProviderConfigEKSTenantUsesIRSA(t *testing.T) {
	doc := renderToMap(t, testAccount(), &types.Cluster{
		ID: "cluster:1", Name: "eks-prod", Distribution: "eks",
		OIDCIssuerURL: "https://oidc.eks.eu-west-1.amazonaws.com/id/ABC",
	})
	if got := nested(doc, "apiVersion"); got != "aws.upbound.io/v1beta1" {
		t.Errorf("apiVersion = %v", got)
	}
	if got := nested(doc, "kind"); got != "ProviderConfig" {
		t.Errorf("kind = %v", got)
	}
	if got := nested(doc, "metadata", "name"); got != "inari-123456789012" {
		t.Errorf("name = %v", got)
	}
	if got := nested(doc, "spec", "credentials", "source"); got != "IRSA" {
		t.Errorf("credentials.source = %v, want IRSA", got)
	}
}

func TestRenderProviderConfigNonEKSUsesWebIdentity(t *testing.T) {
	// kind cluster: metadata only via labels (column fallback).
	doc := renderToMap(t, testAccount(), &types.Cluster{
		ID: "cluster:2", Name: "kind-dev",
		Labels: map[string]string{
			"inari.dev/distribution": "kind",
			"inari.dev/oidc-issuer":  "https://issuer.kind.example",
		},
	})
	if got := nested(doc, "spec", "credentials", "source"); got != "WebIdentity" {
		t.Errorf("credentials.source = %v, want WebIdentity", got)
	}
	if got := nested(doc, "spec", "credentials", "webIdentity", "roleARN"); got != "arn:aws:iam::123456789012:role/inari-crossplane" {
		t.Errorf("webIdentity.roleARN = %v", got)
	}
	if got := nested(doc, "metadata", "annotations", "inari.dev/oidc-issuer"); got != "https://issuer.kind.example" {
		t.Errorf("issuer annotation = %v", got)
	}
}

func TestRenderProviderConfigPlatformRunContextRoleChains(t *testing.T) {
	acct := testAccount()
	acct.RunContext = types.CloudAccountRunContextPlatform
	doc := renderToMap(t, acct, &types.Cluster{
		ID: "cluster:p", Name: "platform-hub", Distribution: "eks",
		OIDCIssuerURL: "https://oidc.eks.example/id/PLATFORM",
	})
	if got := nested(doc, "spec", "credentials", "source"); got != "WebIdentity" {
		t.Errorf("credentials.source = %v, want WebIdentity (platform role chain)", got)
	}
	if got := nested(doc, "metadata", "annotations", "inari.dev/oidc-issuer"); got != "https://oidc.eks.example/id/PLATFORM" {
		t.Errorf("issuer annotation = %v", got)
	}
	chain, ok := nested(doc, "spec", "assumeRoleChain").([]any)
	if !ok || len(chain) != 1 {
		t.Fatalf("assumeRoleChain = %v", nested(doc, "spec", "assumeRoleChain"))
	}
	entry, _ := chain[0].(map[string]any)
	if entry["roleARN"] != acct.RoleARN {
		t.Errorf("assumeRoleChain[0].roleARN = %v", entry["roleARN"])
	}
	if entry["externalID"] != "ext-abc" {
		t.Errorf("assumeRoleChain[0].externalID = %v", entry["externalID"])
	}
}

func TestRenderProviderConfigPlatformNoExternalIDOmitsIt(t *testing.T) {
	acct := testAccount()
	acct.RunContext = types.CloudAccountRunContextPlatform
	acct.ExternalID = ""
	raw, err := RenderProviderConfig(acct, &types.Cluster{OIDCIssuerURL: "https://issuer.example"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "externalID") {
		t.Errorf("externalID should be omitted:\n%s", raw)
	}
}

func TestRenderProviderConfigMissingIssuerErrors(t *testing.T) {
	_, err := RenderProviderConfig(testAccount(), &types.Cluster{ID: "cluster:3", Name: "bare"})
	if err == nil {
		t.Fatal("want error for missing issuer")
	}
	if !strings.Contains(err.Error(), "issuer") {
		t.Errorf("error should name the missing issuer: %v", err)
	}
}
