package deploymentplan

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	observability "github.com/7K-Inari/inari-api/contract/observability/v1"
	"github.com/7K-Inari/inari-server/internal/resourcetargets"
)

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func verifiedResult(t *testing.T, capability *observability.Capability) *observability.VerificationResult {
	t.Helper()
	digest, err := capability.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return &observability.VerificationResult{
		APIVersion: observability.APIVersion, Kind: observability.VerificationKind,
		Companion:        observability.CompanionIdentity{ID: "oc-1", Generation: 3},
		Target:           observability.TargetIdentity{ID: "rt-1", Revision: 7, ClusterID: "cluster-1"},
		App:              observability.AppIdentity{PlanID: "dp-1", InstanceID: "app-1", SourceDigest: testDigest, Revision: "generation-1"},
		Pack:             observability.PackIdentity{ItemID: "hiroba/observability-pack", Version: "0.2.0", Digest: testDigest},
		CapabilityDigest: digest, Suite: observability.SuiteIdentity{Digest: testDigest, Profile: observability.ReadOnlyProfile},
		Run: observability.RunIdentity{ID: "vr-184", Attempt: 1, FinishedAt: time.Date(2026, 11, 15, 21, 42, 0, 0, time.UTC)}, Result: "passed",
		Checks: observability.VerificationChecks{
			Folder:      observability.FolderCheck{Check: observability.Check{State: "passed"}, Name: "acme-inc/payments-api", UID: "folder-1"},
			Dashboards:  []observability.DashboardCheck{{Check: observability.Check{State: "passed"}, UID: "payments-api-overview", Title: "Service overview", Slug: "overview"}},
			Datasources: []observability.DatasourceCheck{{Check: observability.Check{State: "passed"}, Logical: "prometheus", Name: "metrics-central", Type: "prometheus"}},
			Access:      observability.AccessCheck{Check: observability.Check{State: "passed"}, Team: "payments-api-maintainers"},
			Rules:       []observability.RuleCheck{{Check: observability.Check{State: "passed"}, File: "rules/availability.yaml", Evaluation: observability.EvaluationCentral}},
		},
		ExpiresAt: time.Date(2026, 11, 16, 21, 42, 0, 0, time.UTC),
	}
}

func testTarget() resourcetargets.Target {
	return resourcetargets.Target{
		ID: "rt-1", Revision: 7, Enabled: true, ResourceRef: resourcetargets.TargetResourceRef{Kind: "cluster", ID: "cluster-1"},
		Capabilities: []string{resourcetargets.CapabilityMonitoringGrafana}, Config: json.RawMessage(`{"baseUrl":"https://grafana.team.example"}`),
		Readiness: resourcetargets.Readiness{State: resourcetargets.ReadinessReady},
	}
}

func TestVerifiedLinksOnlyForCurrentPassingEvidence(t *testing.T) {
	capability := testCapability()
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	links, err := VerifiedLinks(testTarget(), capability, verifiedResult(t, capability), map[string]string{"namespace": "payments"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || links[0].URL != "https://grafana.team.example/d/payments-api-overview/overview?var-namespace=payments" {
		t.Fatalf("links = %#v", links)
	}
}

func TestNoLinksBeforeReadyOrAfterStaleness(t *testing.T) {
	capability := testCapability()
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		target resourcetargets.Target
		mutate func(*observability.VerificationResult)
		now    time.Time
	}{
		{"no result", testTarget(), func(r *observability.VerificationResult) {}, now},
		{"failed", testTarget(), func(r *observability.VerificationResult) { r.Result = "failed" }, now},
		{"wrong target revision", testTarget(), func(r *observability.VerificationResult) { r.Target.Revision = 6 }, now},
		{"wrong capability", testTarget(), func(r *observability.VerificationResult) { r.CapabilityDigest = testDigest }, now},
		{"expired", testTarget(), func(r *observability.VerificationResult) {}, time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)},
		{"unavailable target", func() resourcetargets.Target {
			target := testTarget()
			target.Readiness.State = resourcetargets.ReadinessUnavailable
			return target
		}(), func(r *observability.VerificationResult) {}, now},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var result *observability.VerificationResult
			if tc.name != "no result" {
				result = verifiedResult(t, capability)
				tc.mutate(result)
			}
			links, err := VerifiedLinks(tc.target, capability, result, map[string]string{"namespace": "payments"}, tc.now)
			if err != nil {
				t.Fatal(err)
			}
			if len(links) != 0 {
				t.Fatalf("fabricated links: %#v", links)
			}
		})
	}
}

func TestLinksRejectUndeclaredOrUnverifiedValues(t *testing.T) {
	capability := testCapability()
	result := verifiedResult(t, capability)
	result.Checks.Folder.Name = "other/folder"
	links, err := VerifiedLinks(testTarget(), capability, result, map[string]string{"namespace": "payments"}, time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 0 {
		t.Fatal("links survived mismatched folder evidence")
	}
	result = verifiedResult(t, capability)
	links, err = VerifiedLinks(testTarget(), capability, result, nil, time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC))
	if err == nil || !strings.Contains(err.Error(), "namespace") {
		t.Fatalf("missing link binding error = %v", err)
	}
	if len(links) != 0 {
		t.Fatal("links returned without declared values")
	}
}
