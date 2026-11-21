package verification

import "time"

// PromotionPolicy links a production target to a source verification stage.
type PromotionPolicy struct {
	ID                  string    `json:"id,omitempty"`
	OrgID               string    `json:"orgId,omitempty"`
	TargetInstanceID    string    `json:"targetInstanceId"`
	SourceInstanceID    string    `json:"sourceInstanceId"`
	Required            bool      `json:"required"`
	RequiredSuiteDigest string    `json:"requiredSuiteDigest"`
	RequiredProfile     string    `json:"requiredProfile"`
	ApproverTeamIDs     []string  `json:"approverTeamIds,omitempty"`
	MaxEvidenceAge      string    `json:"maxEvidenceAge"`
	Revision            int64     `json:"policyRevision"`
	Current             bool      `json:"current,omitempty"`
	CreatedAt           time.Time `json:"createdAt,omitempty"`
	UpdatedAt           time.Time `json:"updatedAt,omitempty"`
}

// PromotionDecision is evidence only; it never triggers promotion.
type PromotionDecision struct {
	Allowed          bool     `json:"allowed"`
	ReasonCode       string   `json:"reasonCode,omitempty"`
	SourceRunID      string   `json:"sourceRunId,omitempty"`
	ApprovalRequired bool     `json:"approvalRequired"`
	ApproverTeamIDs  []string `json:"approverTeamIds,omitempty"`
}
