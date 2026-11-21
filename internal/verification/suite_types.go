package verification

import (
	"time"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/artifactadmission"
)

// Suite describes the signed inari.smoke.v1 manifest.
type Suite struct {
	SuiteSchema           string                  `json:"suiteSchema" yaml:"suiteSchema"`
	Target                SuiteTarget             `json:"target" yaml:"target"`
	CompatibleAppVersions string                  `json:"compatibleAppVersions" yaml:"compatibleAppVersions"`
	ParameterContract     string                  `json:"parameterContract" yaml:"parameterContract"`
	Dependencies          []string                `json:"dependencies" yaml:"dependencies"`
	Timeout               string                  `json:"timeout" yaml:"timeout"`
	ExecutableProfiles    []string                `json:"executableProfiles,omitempty" yaml:"executableProfiles,omitempty"`
	Profiles              map[string]SuiteProfile `json:"profiles" yaml:"profiles"`
	RBACRequirements      []RBACRule              `json:"rbacRequirements" yaml:"rbacRequirements"`
	WorkflowTemplate      string                  `json:"workflowTemplate" yaml:"workflowTemplate"`
	Entrypoint            string                  `json:"entrypoint" yaml:"entrypoint"`
	Idempotency           string                  `json:"idempotency,omitempty" yaml:"idempotency,omitempty"`
	Cleanup               string                  `json:"cleanup,omitempty" yaml:"cleanup,omitempty"`
}

type SuiteTarget struct {
	ID        string       `json:"id" yaml:"id"`
	Version   string       `json:"version" yaml:"version"`
	Component string       `json:"component,omitempty" yaml:"component,omitempty"`
	Adapter   SuiteAdapter `json:"adapter" yaml:"adapter"`
}

type SuiteAdapter struct {
	Kind         string              `json:"kind" yaml:"kind"`
	Path         string              `json:"path,omitempty" yaml:"path,omitempty"`
	ArtifactPath string              `json:"artifactPath,omitempty" yaml:"artifactPath,omitempty"`
	FixtureOnly  bool                `json:"fixtureOnly,omitempty" yaml:"fixtureOnly,omitempty"`
	Readiness    []map[string]string `json:"readiness,omitempty" yaml:"readiness,omitempty"`
}

type SuiteProfile struct {
	SideEffects  string `json:"sideEffects" yaml:"sideEffects"`
	Cleanup      string `json:"cleanup" yaml:"cleanup"`
	Approval     string `json:"approval,omitempty" yaml:"approval,omitempty"`
	ChangeWindow string `json:"changeWindow,omitempty" yaml:"changeWindow,omitempty"`
}

// SuiteRelease is a normalized, cryptographically admitted signed artifact.
type SuiteRelease struct {
	ID                 string                               `json:"id"`
	OrgID              string                               `json:"orgId"`
	SourceID           string                               `json:"sourceId"`
	SuiteDigest        string                               `json:"suiteDigest"`
	SourceFingerprint  string                               `json:"sourceFingerprint"`
	ContentDigest      string                               `json:"contentDigest"`
	Suite              Suite                                `json:"suite"`
	Descriptor         artifactadmission.ArtifactDescriptor `json:"descriptor"`
	WorkflowTemplate   []byte                               `json:"-"`
	TrustTier          trustedsource.TrustTier              `json:"trustTier"`
	Unsigned           bool                                 `json:"unsigned"`
	EvidenceDigest     string                               `json:"evidenceDigest,omitempty"`
	EvidenceFinishedAt time.Time                            `json:"evidenceFinishedAt,omitempty"`
	Eligibility        string                               `json:"eligibility"`
	LegacyException    bool                                 `json:"legacyException,omitempty"`
	AdmittedAt         time.Time                            `json:"admittedAt"`
}
