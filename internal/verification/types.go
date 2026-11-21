// Package verification implements server-authoritative signed-suite
// environment verification without a concrete Workflow renderer.
package verification

import (
	"encoding/json"
	"time"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	contract "github.com/7K-Inari/inari-api/contract/verification/v1"
)

const (
	ProfileCI    = "ci"
	ProfileStage = "stage"
	ProfileProd  = "prod"

	SideEffectReadOnly       = "readOnly"
	SideEffectSyntheticWrite = "syntheticWrite"
	SideEffectMutating       = "mutating"

	AddonAbsentSkip  = "skip"
	AddonAbsentBlock = "block"

	FailureNotify         = "notify"
	FailurePausePromotion = "pausePromotion"
	FailureBlockPromotion = "blockPromotion"
)

// PolicyBinding binds one exact app artifact and signed suite.
type PolicyBinding struct {
	AppItemID         string `json:"appItemId"`
	AppVersion        string `json:"appVersion"`
	AppArtifactDigest string `json:"appArtifactDigest"`
	SpecDigest        string `json:"specDigest"`
	DesiredCommit     string `json:"desiredCommit,omitempty"`
	SuiteGrantID      string `json:"suiteGrantId"`
	SuiteDigest       string `json:"suiteDigest"`
	Profile           string `json:"profile"`
	ParameterContract string `json:"parameterContract"`
}

// TriggerToggle configures one optional trigger.
type TriggerToggle struct {
	Enabled bool `json:"enabled"`
}

// SyncTrigger configures observed ArgoCD sync execution.
type SyncTrigger struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode,omitempty"`
}

// CronConfig configures one schedule set sharing an exact binding/profile.
type CronConfig struct {
	Enabled                 bool     `json:"enabled"`
	ScheduleSetID           string   `json:"scheduleSetId,omitempty"`
	Schedules               []string `json:"schedules,omitempty"`
	Timezone                string   `json:"timezone,omitempty"`
	StartingDeadlineSeconds int64    `json:"startingDeadlineSeconds,omitempty"`
}

// Triggers contains all supported execution sources.
type Triggers struct {
	OnRevisionChange TriggerToggle `json:"onRevisionChange"`
	OnSync           SyncTrigger   `json:"onSync"`
	Manual           TriggerToggle `json:"manual"`
	Cron             CronConfig    `json:"cron"`
}

// ConcurrencyConfig bounds queued and active runs.
type ConcurrencyConfig struct {
	MaxActive            int    `json:"maxActive"`
	MaxPending           int    `json:"maxPending"`
	QueuedRevisionPolicy string `json:"queuedRevisionPolicy"`
}

// RetentionConfig separates Workflow objects from retained result evidence.
type RetentionConfig struct {
	WorkflowTTLSeconds int64 `json:"workflowTTLSeconds"`
	SuccessfulHistory  int   `json:"successfulHistory"`
	FailedHistory      int   `json:"failedHistory"`
	ResultDays         int   `json:"resultDays"`
}

// NotificationConfig selects existing org endpoints; it never carries secrets.
type NotificationConfig struct {
	EndpointIDs []string `json:"endpointIds,omitempty"`
	Events      []string `json:"events,omitempty"`
}

// Policy is one revision of a team-owned verification policy.
type Policy struct {
	ID            string             `json:"id,omitempty"`
	OrgID         string             `json:"orgId,omitempty"`
	InstanceID    string             `json:"instanceId,omitempty"`
	InstanceUID   string             `json:"instanceUid,omitempty"`
	Revision      int64              `json:"policyRevision"`
	Enabled       bool               `json:"enabled"`
	Binding       PolicyBinding      `json:"binding"`
	Triggers      Triggers           `json:"triggers"`
	Timeout       string             `json:"timeout"`
	Concurrency   ConcurrencyConfig  `json:"concurrency"`
	Retention     RetentionConfig    `json:"retention"`
	Notifications NotificationConfig `json:"notifications,omitempty"`
	AddonAbsent   string             `json:"addonAbsent"`
	FailureAction string             `json:"failureAction"`
	Current       bool               `json:"current,omitempty"`
	CreatedAt     time.Time          `json:"createdAt,omitempty"`
	UpdatedAt     time.Time          `json:"updatedAt,omitempty"`
}

// Trigger constructs the canonical contract trigger for this policy.
func (p *Policy) Trigger(kind contract.TriggerKind, sourceID string) contract.Trigger {
	t := contract.Trigger{Kind: kind, Profile: p.Binding.Profile}
	switch kind {
	case contract.TriggerOnSync:
		t.OperationID = sourceID
	case contract.TriggerManual:
		t.RequestKey = sourceID
	case contract.TriggerCron:
		t.ScheduleSetID = p.Triggers.Cron.ScheduleSetID
		t.ScheduledAt = sourceID
	}
	return t
}

// EnvironmentPolicy constrains team choices for one deployment target.
type EnvironmentPolicy struct {
	ID                              string                    `json:"id,omitempty"`
	OrgID                           string                    `json:"orgId,omitempty"`
	TargetID                        string                    `json:"targetId"`
	TargetRevision                  int64                     `json:"targetRevision"`
	Environment                     trustedsource.Environment `json:"environment"`
	Revision                        int64                     `json:"policyRevision"`
	MaxTimeout                      string                    `json:"maxTimeout"`
	MaxActive                       int                       `json:"maxActive"`
	MaxPending                      int                       `json:"maxPending"`
	MinWorkflowTTLSeconds           int64                     `json:"minWorkflowTTLSeconds"`
	MaxWorkflowTTLSeconds           int64                     `json:"maxWorkflowTTLSeconds"`
	MaxResultDays                   int                       `json:"maxResultDays"`
	AllowedProfiles                 []string                  `json:"allowedProfiles"`
	AllowedTriggers                 []string                  `json:"allowedTriggers"`
	AllowedFailureActions           []string                  `json:"allowedFailureActions"`
	RequiredNotificationEndpointIDs []string                  `json:"requiredNotificationEndpointIds,omitempty"`
	CreatedAt                       time.Time                 `json:"createdAt,omitempty"`
	UpdatedAt                       time.Time                 `json:"updatedAt,omitempty"`
}

// RBACRule is a finite declaration checked against platform-approved rules.
type RBACRule struct {
	APIGroups []string `json:"apiGroups" yaml:"apiGroups"`
	Resources []string `json:"resources" yaml:"resources"`
	Verbs     []string `json:"verbs" yaml:"verbs"`
}

// SuiteGrant authorizes exactly one suite digest and profile.
type SuiteGrant struct {
	ID                           string     `json:"id,omitempty"`
	OrgID                        string     `json:"orgId,omitempty"`
	EnvironmentPolicyID          string     `json:"environmentPolicyId,omitempty"`
	SuiteReleaseID               string     `json:"suiteReleaseId"`
	SuiteDigest                  string     `json:"suiteDigest"`
	Profile                      string     `json:"profile"`
	Revision                     int64      `json:"grantRevision"`
	AppItemID                    string     `json:"appItemId,omitempty"`
	AppVersionRange              string     `json:"appVersionRange,omitempty"`
	ParameterContract            string     `json:"parameterContract"`
	SideEffect                   string     `json:"sideEffects"`
	ServiceAccountName           string     `json:"serviceAccountName"`
	ServiceAccountNamespace      string     `json:"serviceAccountNamespace"`
	RBACPolicyDigest             string     `json:"rbacPolicyDigest"`
	AllowedRBAC                  []RBACRule `json:"allowedRbac"`
	EgressPolicyRef              string     `json:"egressPolicyRef"`
	FixtureNamespace             string     `json:"fixtureNamespace,omitempty"`
	CleanupRequired              bool       `json:"cleanupRequired"`
	ApproverTeamIDs              []string   `json:"approverTeamIds,omitempty"`
	RequirePerRunApproval        bool       `json:"requirePerRunApproval"`
	ChangeWindow                 string     `json:"changeWindow,omitempty"`
	MaxTimeout                   string     `json:"maxTimeout"`
	MaxActive                    int        `json:"maxActive"`
	MaxPending                   int        `json:"maxPending"`
	MaxResultBytes               int        `json:"maxResultBytes"`
	ArgoUIBaseURL                string     `json:"argoUiBaseUrl,omitempty"`
	LegacyNonProductionException bool       `json:"legacyNonProductionException,omitempty"`
	ExpiresAt                    *time.Time `json:"expiresAt,omitempty"`
	RevokedAt                    *time.Time `json:"revokedAt,omitempty"`
}

// Run is the durable public execution state.
type Run struct {
	ID                 string           `json:"runId"`
	RunKey             string           `json:"runKey"`
	OrgID              string           `json:"orgId"`
	InstanceID         string           `json:"instanceId"`
	InstanceUID        string           `json:"instanceUid"`
	AppRevision        string           `json:"appRevision"`
	AppArtifactDigest  string           `json:"appArtifactDigest"`
	SuiteDigest        string           `json:"suiteDigest"`
	Profile            string           `json:"profile"`
	Trigger            contract.Trigger `json:"trigger"`
	TriggerFingerprint string           `json:"triggerFingerprint"`
	Status             string           `json:"status"`
	Disposition        string           `json:"disposition,omitempty"`
	ReasonCode         string           `json:"reasonCode,omitempty"`
	Message            string           `json:"message,omitempty"`
	PolicyRevision     int64            `json:"policyRevision"`
	GrantRevision      int64            `json:"grantRevision"`
	LatestAttempt      int              `json:"latestAttempt"`
	Outcome            json.RawMessage  `json:"outcome,omitempty"`
	OutcomeDigest      string           `json:"outcomeDigest,omitempty"`
	ExpiresAt          *time.Time       `json:"expiresAt,omitempty"`
	CreatedAt          time.Time        `json:"createdAt"`
	UpdatedAt          time.Time        `json:"updatedAt"`
}
