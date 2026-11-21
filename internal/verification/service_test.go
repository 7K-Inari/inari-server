package verification_test

import (
	"context"
	"testing"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/artifactadmission"
	"github.com/7K-Inari/inari-server/internal/catalog"
	verification "github.com/7K-Inari/inari-server/internal/verification"
)

type fakeSuiteAdmitter struct {
	admitted *catalog.AdmittedSmokeSuite
	app      *catalog.AdmittedVersion
	calls    int
	appCalls int
}

func (f *fakeSuiteAdmitter) AdmitSmokeSuite(context.Context, string, artifactadmission.ArtifactDescriptor, trustedsource.Environment) (*catalog.AdmittedSmokeSuite, error) {
	f.calls++
	return f.admitted, nil
}
func (f *fakeSuiteAdmitter) AdmitVersion(context.Context, string, string, trustedsource.Environment) (*catalog.AdmittedVersion, error) {
	f.appCalls++
	return f.app, nil
}

func TestPreviewSuiteIsCryptographicAndSideEffectFree(t *testing.T) {
	admitter := &fakeSuiteAdmitter{admitted: admittedSuite()}
	service := verification.NewService(nil, verification.NewStore(), admitter, nil, nil, nil)
	preview, err := service.PreviewSuite(context.Background(), verification.SuiteAdmissionInput{
		OrgID: "org-1", SourceID: "hiroba", Descriptor: admittedSuite().Descriptor,
		Environment: trustedsource.EnvironmentStaging, Profile: verification.ProfileStage,
	})
	if err != nil {
		t.Fatalf("PreviewSuite: %v", err)
	}
	if preview == nil || preview.Release == nil || preview.Release.OrgID != "org-1" || preview.Release.Descriptor.Component != "web" {
		t.Fatalf("unexpected preview: %#v", preview)
	}
	if admitter.calls != 1 || preview.SideEffectsPerformed != 0 || preview.Gate.RenderAvailable || preview.Gate.DeployedVerification {
		t.Fatalf("preview violated side-effect/gate contract: calls=%d preview=%#v", admitter.calls, preview)
	}
}
