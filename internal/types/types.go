// Package types holds minimal local contract types used behind module
// interfaces. Once inari-api tags v0.1.0 these are replaced by the pinned
// contract packages (see AGENTS.md §6).
package types

import (
	"encoding/json"
	"time"
)

type Role string

const (
	RoleOrgAdmin         Role = "org-admin"
	RolePlatformEngineer Role = "platform-engineer"
	RoleDeveloper        Role = "developer"
	RoleViewer           Role = "viewer"
)

func (r Role) Valid() bool {
	switch r {
	case RoleOrgAdmin, RolePlatformEngineer, RoleDeveloper, RoleViewer:
		return true
	}
	return false
}

type Organization struct {
	ID            string    `json:"id"`
	Slug          string    `json:"slug"`
	DisplayName   string    `json:"displayName"`
	KeycloakOrgID string    `json:"keycloakOrgId"`
	CreatedAt     time.Time `json:"createdAt"`
}

type Team struct {
	ID                string    `json:"id"`
	OrgID             string    `json:"orgId"`
	Name              string    `json:"name"`
	KeycloakGroupPath string    `json:"keycloakGroupPath"`
	CreatedAt         time.Time `json:"createdAt"`
}

type User struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
}

type Membership struct {
	UserID string `json:"userId"`
	OrgID  string `json:"orgId"`
	TeamID string `json:"teamId,omitempty"`
	Role   Role   `json:"role"`
}

type AuditEvent struct {
	ID           string          `json:"id"`
	OrgID        string          `json:"orgId"`
	Actor        string          `json:"actor"`
	Impersonator string          `json:"impersonator,omitempty"`
	Action       string          `json:"action"`
	ObjectType   string          `json:"objectType"`
	ObjectID     string          `json:"objectId"`
	Payload      json.RawMessage `json:"payload,omitempty"`
	CreatedAt    time.Time       `json:"createdAt"`
}

type OutboxEvent struct {
	ID          int64           `json:"id"`
	OrgID       string          `json:"orgId"`
	EventType   string          `json:"eventType"`
	Payload     json.RawMessage `json:"payload"`
	OccurredAt  time.Time       `json:"occurredAt"`
	PublishedAt *time.Time      `json:"publishedAt,omitempty"`
}

const (
	EventTenantCreated     = "tenant.created"
	EventTeamCreated       = "team.created"
	EventMembershipAdded   = "membership.added"
	EventMembershipRemoved = "membership.removed"

	EventClusterCreated       = "cluster.created"
	EventClusterRegistered    = "cluster.registered"
	EventClusterRevoked       = "cluster.revoked"
	EventCapabilitiesIngested = "capabilities.ingested"
)

// ClusterState is the cluster lifecycle state (plan §5.11).
type ClusterState string

const (
	ClusterStatePendingApproval     ClusterState = "pending_approval"
	ClusterStatePendingRegistration ClusterState = "pending_registration"
	ClusterStateActive              ClusterState = "active"
	ClusterStateDegraded            ClusterState = "degraded"
	ClusterStateRevoked             ClusterState = "revoked"
)

// Cluster is a registered tenant cluster. It never holds a kubeconfig —
// identity is the per-cluster Keycloak OIDC client only (plan §5.2, §5.10).
type Cluster struct {
	ID                 string            `json:"id"`
	OrgID              string            `json:"orgId"`
	Name               string            `json:"name"`
	KubernetesVersion  string            `json:"kubernetesVersion,omitempty"`
	Labels             map[string]string `json:"labels,omitempty"`
	KeycloakClientID   string            `json:"keycloakClientId,omitempty"`
	State              ClusterState      `json:"state"`
	CapabilityChecksum string            `json:"capabilityChecksum,omitempty"`
	ConnectedAt        *time.Time        `json:"connectedAt,omitempty"`
	LastSeenAt         *time.Time        `json:"lastSeenAt,omitempty"`
	CreatedAt          time.Time         `json:"createdAt"`
}

// RegistrationToken is a one-time, TTL'd bootstrap credential. Only the
// SHA-256 hash is persisted; the plaintext is returned once at issuance.
type RegistrationToken struct {
	ID        string     `json:"id"`
	ClusterID string     `json:"clusterId"`
	ExpiresAt time.Time  `json:"expiresAt"`
	UsedAt    *time.Time `json:"usedAt,omitempty"`
	CreatedBy string     `json:"createdBy"`
	CreatedAt time.Time  `json:"createdAt"`
}

// Capability kinds discovered by the agent (mirror of the inari-api
// CapabilityKind enum; kept as local strings behind the module interface).
type CapabilityKind string

const (
	CapabilityKindCRD                CapabilityKind = "crd"
	CapabilityKindOLMCSV             CapabilityKind = "olm-csv"
	CapabilityKindCrossplaneXRD      CapabilityKind = "crossplane-xrd"
	CapabilityKindCrossplaneProvider CapabilityKind = "crossplane-provider"
	CapabilityKindKRORGD             CapabilityKind = "kro-rgd"
	CapabilityKindHelmRelease        CapabilityKind = "helm-release"
	CapabilityKindClusterAddon       CapabilityKind = "cluster-addon"
	CapabilityKindClusterMetadata    CapabilityKind = "cluster-metadata"
)

// ManagementMode classifies brownfield resources (plan §5.3).
type ManagementMode string

const (
	ManagementModeAdopt       ManagementMode = "adopt"
	ManagementModeObserveOnly ManagementMode = "observe-only"
	ManagementModeIgnore      ManagementMode = "ignore"
)

// CapabilityAction distinguishes upserts from removals.
type CapabilityAction string

const (
	CapabilityActionUpsert CapabilityAction = "upsert"
	CapabilityActionDelete CapabilityAction = "delete"
)

// Capability is one versioned discovered capability record (plan §5.9).
type Capability struct {
	ID             string          `json:"id"`
	ClusterID      string          `json:"clusterId"`
	Kind           CapabilityKind  `json:"kind"`
	Name           string          `json:"name"`
	Group          string          `json:"group,omitempty"`
	Version        string          `json:"version,omitempty"`
	Schema         json.RawMessage `json:"schema,omitempty"`
	UIHints        json.RawMessage `json:"uiHints,omitempty"`
	ManagementMode ManagementMode  `json:"managementMode"`
	FirstSeenAt    time.Time       `json:"firstSeenAt"`
	LastSeenAt     time.Time       `json:"lastSeenAt"`
	DeletedAt      *time.Time      `json:"deletedAt,omitempty"`
}

// CapabilityItem is one item in a capability-update ingest batch.
type CapabilityItem struct {
	Kind           CapabilityKind
	Name           string
	Group          string
	Version        string
	Schema         json.RawMessage
	UIHints        json.RawMessage
	ManagementMode ManagementMode
	Action         CapabilityAction
}

// CapabilityIngest is one capability-update event to persist.
type CapabilityIngest struct {
	FullSync      bool
	Items         []CapabilityItem
	StateChecksum string
}

// CommandStatus is the lifecycle of a dispatched agent command.
type CommandStatus string

const (
	CommandStatusPending   CommandStatus = "pending"
	CommandStatusDelivered CommandStatus = "delivered"
	CommandStatusAcked     CommandStatus = "acked"
	CommandStatusNacked    CommandStatus = "nacked"
)

// AgentCommand is a durable per-agent queue entry. The ID is the
// idempotency key (at-least-once delivery, plan §5.2).
type AgentCommand struct {
	ID            string          `json:"id"`
	ClusterID     string          `json:"clusterId"`
	Type          string          `json:"type"`
	Payload       json.RawMessage `json:"payload"`
	Status        CommandStatus   `json:"status"`
	Attempts      int             `json:"attempts"`
	ResultMessage string          `json:"resultMessage,omitempty"`
	CreatedAt     time.Time       `json:"createdAt"`
	UpdatedAt     time.Time       `json:"updatedAt"`
}

// ClusterPayload is the outbox payload for cluster lifecycle events.
type ClusterPayload struct {
	OrgID     string `json:"orgId"`
	ClusterID string `json:"clusterId"`
	Name      string `json:"name,omitempty"`
}

// CapabilitiesIngestedPayload summarizes one persisted capability update.
type CapabilitiesIngestedPayload struct {
	OrgID         string `json:"orgId"`
	ClusterID     string `json:"clusterId"`
	Upserted      int    `json:"upserted"`
	Deleted       int    `json:"deleted"`
	FullSync      bool   `json:"fullSync"`
	StateChecksum string `json:"stateChecksum"`
}

// TeamSeed is one default team to create with a tenant and the org role it grants.
type TeamSeed struct {
	TeamID string `json:"teamId"`
	Name   string `json:"name"`
	Role   Role   `json:"role"`
}

// TenantCreatedPayload is the outbox payload for EventTenantCreated.
type TenantCreatedPayload struct {
	OrgID string     `json:"orgId"`
	Slug  string     `json:"slug"`
	Teams []TeamSeed `json:"teams"`
}

// TeamCreatedPayload is the outbox payload for EventTeamCreated.
type TeamCreatedPayload struct {
	OrgID  string `json:"orgId"`
	TeamID string `json:"teamId"`
	Name   string `json:"name"`
	Role   Role   `json:"role"`
}

// MembershipPayload is the outbox payload for membership add/remove events.
type MembershipPayload struct {
	OrgID  string `json:"orgId"`
	TeamID string `json:"teamId"`
	UserID string `json:"userId"`
	Role   Role   `json:"role"`
}
