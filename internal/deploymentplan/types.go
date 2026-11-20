// Package deploymentplan normalizes deployment sources and optional
// observability companions without taking over artifact admission or target
// authorization from their owning services.
package deploymentplan

import (
	"encoding/json"
	"time"

	observability "github.com/7K-Inari/inari-api/contract/observability/v1"
	"github.com/7K-Inari/inari-server/internal/resourcetargets"
)

type SourceKind string

const (
	SourceCatalog  SourceKind = "catalog"
	SourceChart    SourceKind = "chart"
	SourceTemplate SourceKind = "template"
)

type Operation string

const (
	OperationDeploy            Operation = "deploy"
	OperationProvisionExisting Operation = "provisionExisting"
)

type ObservabilityMode string

const (
	ModeNone      ObservabilityMode = "none"
	ModeSkip      ObservabilityMode = "skip"
	ModeProvision ObservabilityMode = "provision"
)

type Source struct {
	Kind             SourceKind `json:"kind"`
	ItemID           string     `json:"itemId,omitempty"`
	Version          string     `json:"version,omitempty"`
	SourceID         string     `json:"sourceId,omitempty"`
	Ref              string     `json:"ref,omitempty"`
	Digest           string     `json:"digest,omitempty"`
	AdmissionItemID  string     `json:"admissionItemId,omitempty"`
	AdmissionVersion string     `json:"admissionVersion,omitempty"`
	DisplayName      string     `json:"displayName,omitempty"`
}

type ArtifactPin struct {
	ItemID         string `json:"itemId,omitempty"`
	Version        string `json:"version"`
	PackageVersion string `json:"packageVersion,omitempty"`
	Ref            string `json:"ref,omitempty"`
	Digest         string `json:"digest"`
	SourceID       string `json:"sourceId,omitempty"`
	ChartRef       string `json:"chartRef,omitempty"`
	ChartDigest    string `json:"chartDigest,omitempty"`
}

type PackPin struct {
	ArtifactPin
	RenderContract string `json:"renderContract"`
}

type DeploymentInput struct {
	TargetID       string          `json:"targetId"`
	TargetRevision int64           `json:"targetRevision"`
	RepoID         string          `json:"repoId,omitempty"`
	Name           string          `json:"name,omitempty"`
	Namespace      string          `json:"namespace,omitempty"`
	OwnerTeam      string          `json:"ownerTeam,omitempty"`
	Spec           json.RawMessage `json:"spec,omitempty"`
	DisplayName    string          `json:"displayName,omitempty"`
}

type TargetIntent struct {
	ID        string          `json:"id"`
	Revision  int64           `json:"revision"`
	Selection json.RawMessage `json:"selection"`
}

type ObservabilityInput struct {
	Mode   ObservabilityMode `json:"mode"`
	Pack   *PackPin          `json:"pack,omitempty"`
	Target *TargetIntent     `json:"target,omitempty"`
}

type PlanRequest struct {
	Operation       Operation          `json:"operation"`
	InstanceID      string             `json:"instanceId,omitempty"`
	Source          *Source            `json:"source,omitempty"`
	Deployment      DeploymentInput    `json:"deployment"`
	Observability   ObservabilityInput `json:"observability"`
	PlanFingerprint string             `json:"planFingerprint,omitempty"`
	IdempotencyKey  string             `json:"idempotencyKey"`
}

type GateStatus struct {
	CompanionRendering   bool   `json:"companionRendering"`
	DeployedVerification bool   `json:"deployedVerification"`
	Reason               string `json:"reason,omitempty"`
}

type RenderIntent struct {
	AppSpec    json.RawMessage          `json:"appSpec,omitempty"`
	PackSpec   map[string]any           `json:"packSpec,omitempty"`
	Evaluation observability.Evaluation `json:"evaluation,omitempty"`
}

type Link struct {
	Title string `json:"title"`
	UID   string `json:"uid"`
	URL   string `json:"url"`
}

type Companion struct {
	ID                  string                            `json:"id"`
	PlanID              string                            `json:"planId"`
	AppInstanceID       string                            `json:"appInstanceId,omitempty"`
	ScaffoldRunID       string                            `json:"scaffoldRunId,omitempty"`
	CompanionInstanceID string                            `json:"companionInstanceId,omitempty"`
	TargetID            string                            `json:"targetId"`
	TargetRevision      int64                             `json:"targetRevision"`
	TargetClusterID     string                            `json:"targetClusterId"`
	TargetSelection     json.RawMessage                   `json:"targetSelection"`
	AppSourceDigest     string                            `json:"appSourceDigest"`
	AppRevision         string                            `json:"appRevision"`
	Pack                PackPin                           `json:"pack"`
	CapabilityDigest    string                            `json:"capabilityDigest"`
	State               string                            `json:"state"`
	Generation          int64                             `json:"generation"`
	Verification        *observability.VerificationResult `json:"verification,omitempty"`
	Links               []Link                            `json:"links"`
	Reason              string                            `json:"reason,omitempty"`
	CreatedAt           time.Time                         `json:"createdAt"`
	UpdatedAt           time.Time                         `json:"updatedAt"`
}

type Plan struct {
	ID               string                    `json:"id"`
	OrgID            string                    `json:"orgId"`
	OrgSlug          string                    `json:"orgSlug"`
	Requester        string                    `json:"-"`
	IdempotencyKey   string                    `json:"-"`
	Operation        Operation                 `json:"operation"`
	Source           Source                    `json:"source"`
	Deployment       DeploymentInput           `json:"deployment"`
	App              ArtifactPin               `json:"app"`
	Capability       *observability.Capability `json:"capability,omitempty"`
	CapabilityDigest string                    `json:"capabilityDigest,omitempty"`
	Observability    ObservabilityInput        `json:"observability"`
	RenderIntent     *RenderIntent             `json:"renderIntent,omitempty"`
	PlanFingerprint  string                    `json:"planFingerprint"`
	State            string                    `json:"state"`
	Gate             GateStatus                `json:"gate"`
	AppInstanceID    string                    `json:"appInstanceId,omitempty"`
	AppClusterID     string                    `json:"appClusterId,omitempty"`
	ScaffoldRunID    string                    `json:"scaffoldRunId,omitempty"`
	CommitSHA        string                    `json:"commitSha,omitempty"`
	PRURL            string                    `json:"prUrl,omitempty"`
	ApprovalID       string                    `json:"approvalId,omitempty"`
	Companion        *Companion                `json:"companion,omitempty"`
	ErrorCode        string                    `json:"errorCode,omitempty"`
	ErrorMessage     string                    `json:"errorMessage,omitempty"`
	CreatedAt        time.Time                 `json:"createdAt"`
	UpdatedAt        time.Time                 `json:"updatedAt"`
}

type Preflight struct {
	Plan              Plan                                 `json:"plan"`
	Schema            json.RawMessage                      `json:"schema,omitempty"`
	UIHints           json.RawMessage                      `json:"uiHints,omitempty"`
	DeploymentTargets []resourcetargets.Target             `json:"deploymentTargets"`
	MonitoringTargets []resourcetargets.Target             `json:"monitoringTargets"`
	CompatiblePacks   []PackPin                            `json:"compatiblePacks"`
	Providers         []resourcetargets.ProviderDescriptor `json:"providers"`
}

type InstanceObservability struct {
	Mode      ObservabilityMode `json:"mode"`
	Available bool              `json:"available"`
	Reason    string            `json:"reason,omitempty"`
	Companion *Companion        `json:"companion,omitempty"`
}
