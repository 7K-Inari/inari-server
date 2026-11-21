package verification_test

import (
	"strings"
	"testing"
	"time"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/artifactadmission"
	"github.com/7K-Inari/inari-server/internal/catalog"
	verification "github.com/7K-Inari/inari-server/internal/verification"
)

const validSuiteYAML = `suiteSchema: inari.smoke.v1
target:
  id: web
  version: 1.0.0
  component: packages/web
  adapter:
    kind: manifests
    fixtureOnly: false
    artifactPath: manifests.yaml
    readiness: []
executableProfiles: [ci, stage, prod]
compatibleAppVersions: ">=1.0.0 <2.0.0"
parameterContract: inari.smoke.params.v1
dependencies: []
timeout: 5m
profiles:
  ci: {sideEffects: readOnly, cleanup: required}
  stage: {sideEffects: readOnly, cleanup: required}
  prod: {sideEffects: readOnly, cleanup: required}
rbacRequirements:
  - apiGroups: [""]
    resources: [pods]
    verbs: [get, list]
workflowTemplate: workflowtemplate.yaml
entrypoint: smoke
idempotency: safe
cleanup: no resources are created by the read-only journey
`

const validWorkflowYAML = `apiVersion: argoproj.io/v1alpha1
kind: WorkflowTemplate
metadata:
  name: web-smoke
spec:
  entrypoint: smoke
  onExit: cleanup
  templates:
    - name: smoke
      container:
        image: ghcr.io/7k-hiroba/example/verify@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
        command: [check]
    - name: cleanup
      container:
        image: ghcr.io/7k-hiroba/example/verify@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
        command: [cleanup]
`

func admittedSuite(mutate ...func(*catalog.AdmittedSmokeSuite)) *catalog.AdmittedSmokeSuite {
	fixture := false
	eligible := true
	a := &catalog.AdmittedSmokeSuite{
		Source:            trustedsource.Source{ID: "hiroba", TrustTier: trustedsource.TrustOfficial},
		SourceFingerprint: "source-fingerprint",
		Descriptor: artifactadmission.ArtifactDescriptor{
			Ref: "ghcr.io/7k-hiroba/example/smoke/web:1.0.0", Digest: digestC,
			MediaType: trustedsource.SmokeSuiteMediaType, PackageVersion: "1.0.0", Component: "web", App: "example",
		},
		Evidence: &artifactadmission.EvidenceSummary{
			ArtifactDigest: digestC, TestEvidenceDigest: digestB,
			Files: map[string][]byte{"suite.yaml": []byte(validSuiteYAML), "workflowtemplate.yaml": []byte(validWorkflowYAML), "manifests.yaml": []byte("kind: Deployment\n")},
			TestEvidence: &trustedsource.TestEvidence{
				TargetAdapter: "manifests", FixtureOnly: &fixture, ExecutableProfiles: []string{"ci", "stage", "prod"},
				EvidenceScope: trustedsource.EvidenceScopeApplication, AppEvidenceEligible: &eligible,
			},
		},
	}
	for _, fn := range mutate {
		fn(a)
	}
	return a
}

func TestParseSuiteArtifact(t *testing.T) {
	got, err := verification.ParseSuiteArtifact(admittedSuite(), verification.ProfileStage, trustedsource.EnvironmentStaging, false, time.Now())
	if err != nil {
		t.Fatalf("valid suite rejected: %v", err)
	}
	if got == nil || got.SuiteDigest != digestC || got.Suite.Target.Component != "packages/web" || got.Eligibility != "application" || got.ContentDigest == "" {
		t.Fatalf("unexpected release: %#v", got)
	}
	if _, err := verification.ParseSuiteArtifact(admittedSuite(func(a *catalog.AdmittedSmokeSuite) { a.Descriptor.Component = "other" }), verification.ProfileStage, trustedsource.EnvironmentStaging, false, time.Now()); err == nil || !strings.Contains(err.Error(), "component") {
		t.Fatalf("component mismatch error = %v", err)
	}
	legacy := admittedSuite(func(a *catalog.AdmittedSmokeSuite) { a.Evidence.TestEvidence = &trustedsource.TestEvidence{} })
	if _, err := verification.ParseSuiteArtifact(legacy, verification.ProfileStage, trustedsource.EnvironmentStaging, false, time.Now()); err == nil || !strings.Contains(err.Error(), trustedsource.CodeSuiteEligibilityUnknown) {
		t.Fatalf("legacy staging error = %v", err)
	}
	if _, err := verification.ParseSuiteArtifact(legacy, verification.ProfileStage, trustedsource.EnvironmentDevelopment, true, time.Now()); err != nil {
		t.Fatalf("exact artifact-bound development legacy exception rejected: %v", err)
	}
	multipleDocuments := admittedSuite(func(a *catalog.AdmittedSmokeSuite) {
		a.Evidence.Files["suite.yaml"] = []byte(validSuiteYAML + "---\nsuiteSchema: inari.smoke.v1\n")
	})
	if _, err := verification.ParseSuiteArtifact(multipleDocuments, verification.ProfileStage, trustedsource.EnvironmentStaging, false, time.Now()); err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("multiple suite documents error = %v", err)
	}
}

func TestWorkflowTemplateSafety(t *testing.T) {
	suite := &verification.Suite{Entrypoint: "smoke"}
	grant := validGrant()
	if err := verification.ValidateWorkflowTemplate([]byte(validWorkflowYAML), suite, grant); err != nil {
		t.Fatalf("valid WorkflowTemplate rejected: %v", err)
	}
	tests := []struct {
		name, old, replacement, want string
	}{
		{name: "service account override", old: "  entrypoint: smoke", replacement: "  entrypoint: smoke\n  serviceAccountName: admin", want: "serviceAccountName"},
		{name: "suite created RBAC", old: "    - name: smoke\n      container:", replacement: "    - name: smoke\n      resource:\n        action: create\n        manifest: |\n          kind: RoleBinding\n      container:", want: "resource templates"},
		{name: "mutable image", old: "image: ghcr.io/7k-hiroba/example/verify@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", replacement: "image: ghcr.io/7k-hiroba/example/verify:latest", want: "digest-pinned"},
		{name: "external template", old: "    - name: smoke\n      container:", replacement: "    - name: smoke\n      templateRef:\n        name: privileged\n      container:", want: "templateRef"},
		{name: "host path", old: "  entrypoint: smoke", replacement: "  entrypoint: smoke\n  volumes:\n    - name: host\n      hostPath: {path: /}", want: "hostPath"},
		{name: "synchronization override", old: "  entrypoint: smoke", replacement: "  entrypoint: smoke\n  synchronization:\n    semaphore: {}", want: "synchronization"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := strings.Replace(validWorkflowYAML, tt.old, tt.replacement, 1)
			if err := verification.ValidateWorkflowTemplate([]byte(raw), suite, grant); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
	if err := verification.ValidateWorkflowTemplate([]byte(validWorkflowYAML+"---\napiVersion: argoproj.io/v1alpha1\nkind: Workflow\n"), suite, grant); err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("multiple Workflow documents error = %v", err)
	}
}
