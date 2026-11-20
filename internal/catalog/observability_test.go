package catalog

import (
	"encoding/json"
	"strings"
	"testing"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
)

const observabilityTestDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

const testObservabilityYAML = `apiVersion: inari.dev/v1alpha1
kind: Observability
app: payments-api
folder: payments-api
datasources:
  prometheus: ${DS_PROMETHEUS}
linkVariables: [namespace]
dashboards:
  - title: Service overview
    uid: payments-api-overview
    file: dashboards/overview.json
rules:
  - file: rules/availability.yaml
    evaluation: central
targets: [central, local]
severityRouting:
  critical: platform-security
minimumAppVersion: ">=1.3.0 <2.0.0"
observabilityPack:
  package: observability-pack
  versionRange: ">=0.2.0 <0.3.0"
`

func TestPackageObservabilitySurvivesSignedSnapshot(t *testing.T) {
	entry := trustedsource.IndexEntry{
		Name: "payments-api", Version: "1.4.0", PackageVersion: "1.4.0", Channel: "stable", Type: "kro-rgd",
		Digest: observabilityTestDigest, MediaType: trustedsource.CatalogPackageMediaType,
	}
	files := map[string][]byte{
		"package.yaml":       []byte("version: 1.4.0\nchannel: stable\ntype: kro-rgd\ndescription: Payments\ncategory: test\nobservability:\n  package: observability-pack\n  versionRange: '>=0.2.0 <0.3.0'\n"),
		"observability.yaml": []byte(testObservabilityYAML),
		"rgd.yaml":           []byte("apiVersion: kro.run/v1alpha1\nkind: ResourceGraphDefinition\n"),
	}
	packages, err := packageFromFiles(entry, "registry.local/core/payments-api@"+observabilityTestDigest, files)
	if err != nil {
		t.Fatal(err)
	}
	_, versions, err := syncPlan("core", packages)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(versions[0].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["observabilityYaml"] != testObservabilityYAML {
		t.Fatalf("signed observability metadata missing from payload: %s", versions[0].Payload)
	}
	ref, ok := payload["observabilityRef"].(map[string]any)
	if !ok || ref["package"] != "observability-pack" || !strings.Contains(ref["versionRange"].(string), "0.2.0") {
		t.Fatalf("package observability reference missing: %#v", payload["observabilityRef"])
	}
}
