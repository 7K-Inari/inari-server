package verification

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/artifactadmission"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/resourcetargets"
	"github.com/7K-Inari/inari-server/internal/types"
)

const ExternalGateReason = "sibling_8f8c472a_phase_3_unconfirmed"

// SuiteAdmitter is implemented by catalog.Service.
type SuiteAdmitter interface {
	AdmitSmokeSuite(ctx context.Context, sourceID string, descriptor artifactadmission.ArtifactDescriptor, environment trustedsource.Environment) (*catalog.AdmittedSmokeSuite, error)
	AdmitVersion(ctx context.Context, itemID, version string, environment trustedsource.Environment) (*catalog.AdmittedVersion, error)
}

// InstanceGetter is implemented by inventory.Store.
type InstanceGetter interface {
	Get(ctx context.Context, q db.Querier, id string) (*types.ResourceInstance, error)
}

// TargetResolver is the shared deployment-target policy enforcement point.
type TargetResolver interface {
	ResolveResource(ctx context.Context, orgID, subject, capability string, action resourcetargets.Action, ref resourcetargets.TargetResourceRef, selection json.RawMessage) (*resourcetargets.ResolvedTarget, error)
}

// GateStatus reports external execution availability without bypass flags.
type GateStatus struct {
	RenderAvailable      bool   `json:"renderAvailable"`
	DeployedVerification bool   `json:"deployedVerification"`
	Reason               string `json:"reason,omitempty"`
}

// SuiteAdmissionInput is accepted only from platform management routes.
type SuiteAdmissionInput struct {
	OrgID                        string                               `json:"-"`
	SourceID                     string                               `json:"sourceId"`
	Descriptor                   artifactadmission.ArtifactDescriptor `json:"descriptor"`
	Environment                  trustedsource.Environment            `json:"environment"`
	Profile                      string                               `json:"profile"`
	LegacyNonProductionException bool                                 `json:"legacyNonProductionException,omitempty"`
}

// SuitePreview is a read-only admission result.
type SuitePreview struct {
	Release              *SuiteRelease `json:"release"`
	Gate                 GateStatus    `json:"gate"`
	Warnings             []string      `json:"warnings,omitempty"`
	SideEffectsPerformed int           `json:"sideEffectsPerformed"`
}

// Service coordinates verification policy and admission. No concrete renderer
// is registered while the external gate is closed.
type Service struct {
	db            *db.DB
	store         *Store
	suites        SuiteAdmitter
	instances     InstanceGetter
	targets       TargetResolver
	audit         *audit.Store
	observability ObservabilityReportConsumer
	now           func() time.Time
}

func NewService(d *db.DB, store *Store, suites SuiteAdmitter, instances InstanceGetter, targets TargetResolver, auditStore *audit.Store) *Service {
	if store == nil {
		store = NewStore()
	}
	return &Service{db: d, store: store, suites: suites, instances: instances, targets: targets, audit: auditStore, now: time.Now}
}

func (s *Service) GateStatus() GateStatus {
	return GateStatus{RenderAvailable: false, DeployedVerification: false, Reason: ExternalGateReason}
}

// PreviewSuite performs cryptographic and static validation with no persistence.
func (s *Service) PreviewSuite(ctx context.Context, input SuiteAdmissionInput) (*SuitePreview, error) {
	if s.suites == nil {
		return nil, &artifactadmission.Error{Code: artifactadmission.CodeUnavailable, Err: errors.New("suite admission is not configured"), Temporary: true}
	}
	if input.Profile == "" {
		return nil, errors.New("profile is required")
	}
	admitted, err := s.suites.AdmitSmokeSuite(ctx, input.SourceID, input.Descriptor, input.Environment)
	if err != nil {
		return nil, err
	}
	release, err := ParseSuiteArtifact(admitted, input.Profile, input.Environment, input.LegacyNonProductionException, s.now())
	if err != nil {
		return nil, err
	}
	release.OrgID = input.OrgID
	release.Descriptor = admitted.Descriptor
	profile := release.Suite.Profiles[input.Profile]
	if err := ValidateWorkflowTemplate(release.WorkflowTemplate, &release.Suite, &SuiteGrant{SideEffect: profile.SideEffects}); err != nil {
		return nil, err
	}
	preview := &SuitePreview{Release: release, Gate: s.GateStatus(), SideEffectsPerformed: 0}
	if release.LegacyException {
		preview.Warnings = append(preview.Warnings, "legacy_eligibility_exception: exact signed artifact-bound non-production/non-evidence exception")
	}
	return preview, nil
}

// Compile-time interface documentation for the production wiring.
var _ InstanceGetter = (*inventory.Store)(nil)
