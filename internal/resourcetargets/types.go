// Package resourcetargets resolves secret-free, RBAC-enforced overlays over
// existing org inventory. Target rows never replace the backing resource.
package resourcetargets

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/7K-Inari/inari-server/internal/types"
)

const (
	CapabilityDeploymentCluster = "deployment.cluster"
	CapabilityMonitoringGrafana = "monitoring.grafana"
	ResourceKindCluster         = "cluster"
	RendererArgoCD              = "argocd"
)

type Action string

const (
	ActionView      Action = "view"
	ActionUse       Action = "use"
	ActionProvision Action = "provision"
)

func (a Action) Valid() bool {
	return a == ActionView || a == ActionUse || a == ActionProvision
}

type ResourceRef struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

type Binding struct {
	Renderer       string `json:"renderer,omitempty"`
	ClusterID      string `json:"clusterId,omitempty"`
	BaselineRepoID string `json:"baselineRepoId,omitempty"`
	BaseBranch     string `json:"baseBranch,omitempty"`
	CommitPolicy   string `json:"commitPolicy,omitempty"`
}

type ReadinessState string

const (
	ReadinessReady       ReadinessState = "ready"
	ReadinessDegraded    ReadinessState = "degraded"
	ReadinessUnavailable ReadinessState = "unavailable"
)

func (s ReadinessState) Selectable() bool { return s == ReadinessReady || s == ReadinessDegraded }

type Readiness struct {
	State      ReadinessState `json:"state"`
	Reasons    []string       `json:"reasons,omitempty"`
	ObservedAt *time.Time     `json:"observedAt,omitempty"`
}

type Grant struct {
	TargetID  string    `json:"targetId"`
	TeamID    string    `json:"teamId"`
	Relation  Action    `json:"relation"`
	CreatedBy string    `json:"createdBy,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type Target struct {
	ID               string          `json:"id"`
	OrgID            string          `json:"orgId"`
	Name             string          `json:"name"`
	ResourceRef      ResourceRef     `json:"resourceRef"`
	Capabilities     []string        `json:"capabilities"`
	Config           json.RawMessage `json:"config"`
	Enabled          bool            `json:"enabled"`
	IsDefault        bool            `json:"isDefault"`
	Revision         int64           `json:"revision"`
	Binding          Binding         `json:"binding"`
	Readiness        Readiness       `json:"readiness"`
	EffectiveActions []Action        `json:"effectiveActions,omitempty"`
	Grants           []Grant         `json:"grants,omitempty"`
	CreatedBy        string          `json:"-"`
	CreatedAt        time.Time       `json:"createdAt"`
	UpdatedAt        time.Time       `json:"updatedAt"`
}

func (t *Target) Capability() string {
	if t == nil || len(t.Capabilities) == 0 {
		return ""
	}
	return t.Capabilities[0]
}

type ApprovalPolicy struct {
	Required        bool     `json:"required"`
	ApproverTeamIDs []string `json:"approverTeamIds,omitempty"`
}

type CreateInput struct {
	Name        string
	ResourceRef ResourceRef
	Capability  string
	Config      json.RawMessage
	IsDefault   bool
}

type PatchInput struct {
	Name      *string
	Config    *json.RawMessage
	Enabled   *bool
	IsDefault *bool
	Revision  int64
}

type ListFilter struct {
	Capability         string
	ResourceRef        *ResourceRef
	Action             Action
	IncludeUnavailable bool
}

type ResolveInput struct {
	OrgID            string
	Subject          string
	TargetID         string
	Capability       string
	Action           Action
	ExpectedRevision int64
	Selection        json.RawMessage
}

type ResolvedTarget struct {
	Target    Target
	Selection json.RawMessage
	Approval  ApprovalPolicy
	Cluster   *types.Cluster
}

type ResourceSnapshot struct {
	Cluster      *types.Cluster
	BaselineRepo *types.TenantGitRepo
	Addons       []*types.ClusterAddon
	Capabilities []types.Capability
	TeamIDs      []string
}

var (
	ErrTargetNotFound = errors.New("resource target not found")
	ErrTargetDenied   = errors.New("resource target grant required")
	ErrConflict       = errors.New("resource target conflict")
	ErrStaleRevision  = errors.New("resource target revision is stale")
	ErrUnavailable    = errors.New("resource target is unavailable")
	ErrInvalidInput   = errors.New("resource target invalid input")
)

type FieldError struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

type ValidationError struct {
	Fields []FieldError
}

func (e *ValidationError) Error() string {
	parts := make([]string, 0, len(e.Fields))
	for _, f := range e.Fields {
		parts = append(parts, fmt.Sprintf("%s: %s", f.Path, f.Message))
	}
	return "resource target validation failed: " + strings.Join(parts, "; ")
}

func invalid(path, message string) error {
	return &ValidationError{Fields: []FieldError{{Path: path, Message: message}}}
}
