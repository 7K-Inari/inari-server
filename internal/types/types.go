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

	EventClusterCreated        = "cluster.created"
	EventClusterRegistered     = "cluster.registered"
	EventClusterRevoked        = "cluster.revoked"
	EventClusterCordoned       = "cluster.cordoned"
	EventClusterUncordoned     = "cluster.uncordoned"
	EventClusterDecommissioned = "cluster.decommissioned"
	EventCapabilitiesIngested  = "capabilities.ingested"

	EventCatalogItemUpserted = "catalog.item_upserted"
	EventApprovalRequested   = "approval.requested"
	EventApprovalDecided     = "approval.decided"
	EventApprovalCancelled   = "approval.cancelled"
	EventApprovalExpired     = "approval.expired"
	EventDeployRequested     = "deploy.requested"
	EventInstanceCreated     = "instance.created"
	EventInstanceStatus      = "instance.status"
	EventInstanceUpgraded    = "instance.upgraded"

	EventCloudAccountRegistered   = "cloud_account.registered"
	EventCloudAccountValidated    = "cloud_account.validated"
	EventCloudAccountDeregistered = "cloud_account.deregistered"

	EventPolicyPackAssigned = "policy_pack.assigned"
	EventClusterSetCreated  = "cluster_set.created"
	EventClusterSetDeleted  = "cluster_set.deleted"
	EventExemptionRequested = "exemption.requested"
	EventExemptionDecided   = "exemption.decided"
)

// ClusterState is the cluster lifecycle state (plan §5.11).
type ClusterState string

const (
	ClusterStatePendingApproval     ClusterState = "pending_approval"
	ClusterStatePendingRegistration ClusterState = "pending_registration"
	ClusterStateActive              ClusterState = "active"
	ClusterStateDegraded            ClusterState = "degraded"
	ClusterStateCordoned            ClusterState = "cordoned"
	ClusterStateDecommissioned      ClusterState = "decommissioned"
	ClusterStateRevoked             ClusterState = "revoked"
)

// Cluster is a registered tenant cluster. It never holds a kubeconfig —
// identity is the per-cluster Keycloak OIDC client only (plan §5.2, §5.10).
type Cluster struct {
	ID                 string            `json:"id"`
	OrgID              string            `json:"orgId"`
	Name               string            `json:"name"`
	KubernetesVersion  string            `json:"kubernetesVersion,omitempty"`
	Distribution       string            `json:"distribution,omitempty"` // e.g. "eks", "kind" (agent-reported)
	OIDCIssuerURL      string            `json:"oidcIssuerUrl,omitempty"`
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

// CatalogSource identifies which of the three catalog sources an item came
// from (plan §5.5).
type CatalogSource string

const (
	CatalogSourceDiscovered CatalogSource = "discovered"
	CatalogSourceCurated    CatalogSource = "curated"
	CatalogSourcePlatform   CatalogSource = "platform"
)

// ApprovalPolicy gates deploy requests per catalog item (plan §5.2).
type ApprovalPolicy string

const (
	ApprovalPolicyAuto          ApprovalPolicy = "auto"
	ApprovalPolicyPeer          ApprovalPolicy = "peer"
	ApprovalPolicyPlatformAdmin ApprovalPolicy = "platform-admin"
)

// CapabilityRef points a discovered-source catalog item at its capability.
type CapabilityRef struct {
	Kind  CapabilityKind `json:"kind"`
	Group string         `json:"group,omitempty"`
	Name  string         `json:"name"`
}

// CatalogItem is the normalized catalog entry (plan §5.9).
type CatalogItem struct {
	ID             string         `json:"id"`
	Source         CatalogSource  `json:"source"`
	Name           string         `json:"name"`
	DisplayName    string         `json:"displayName"`
	Description    string         `json:"description"`
	CapabilityRef  *CapabilityRef `json:"capabilityRef,omitempty"`
	OCIRef         string         `json:"ociRef,omitempty"`
	ApprovalPolicy ApprovalPolicy `json:"approvalPolicy"`
	CreatedAt      time.Time      `json:"createdAt"`
}

// CatalogItemVersion is one versioned revision of an item with its OpenAPI
// v3 schema, UI hints, and payload (RGD YAML / platform app ref).
type CatalogItemVersion struct {
	ID      string          `json:"id"`
	ItemID  string          `json:"itemId"`
	Version string          `json:"version"`
	Channel string          `json:"channel"`
	Schema  json.RawMessage `json:"schema,omitempty"`
	UIHints json.RawMessage `json:"uiHints,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// VisibilityRule scopes a catalog item to tenants/clusters ("*" = all).
type VisibilityRule struct {
	ItemID    string `json:"itemId"`
	OrgID     string `json:"orgId"`
	ClusterID string `json:"clusterId"`
}

// VersionPin pins a tenant to a specific catalog item version.
type VersionPin struct {
	OrgID   string `json:"orgId"`
	ItemID  string `json:"itemId"`
	Version string `json:"version"`
}

// Approval states.
const (
	ApprovalStatePending   = "pending"
	ApprovalStateApproved  = "approved"
	ApprovalStateRejected  = "rejected"
	ApprovalStateCancelled = "cancelled"
	ApprovalStateExpired   = "expired"
)

// Lifecycle approval actions (plan §5.11/§5.12): generic approval-gated
// control-plane operations that are not catalog deploys.
const (
	ApprovalActionTenantZoneVend         = "tenant_zone.vend"
	ApprovalActionTenantZoneDecommission = "tenant_zone.decommission"
)

// ApprovalRequest gates one deploy request (plan §5.2). Name, Namespace,
// OwnerTeam, Channel and InstanceID carry the deploy context so an approved
// request can be resumed by the orchestrator without the caller re-issuing
// the deploy (M3); InstanceID is set for upgrade approvals. For lifecycle
// approvals (Action set, ItemID empty), Spec carries the action context.
type ApprovalRequest struct {
	ID          string          `json:"id"`
	OrgID       string          `json:"orgId"`
	ItemID      string          `json:"itemId"`
	Version     string          `json:"version"`
	ClusterID   string          `json:"clusterId"`
	Spec        json.RawMessage `json:"spec"`
	Requester   string          `json:"requester"`
	Approver    string          `json:"approver,omitempty"`
	State       string          `json:"state"`
	Reason      string          `json:"reason,omitempty"`
	Name        string          `json:"name,omitempty"`
	Namespace   string          `json:"namespace,omitempty"`
	OwnerTeam   string          `json:"ownerTeam,omitempty"`
	Channel     string          `json:"channel,omitempty"`
	InstanceID  string          `json:"instanceId,omitempty"`
	Action      string          `json:"action,omitempty"`
	CreatedAt   time.Time       `json:"createdAt"`
	DecidedAt   *time.Time      `json:"decidedAt,omitempty"`
	ExpiresAt   *time.Time      `json:"expiresAt,omitempty"`
	CancelledBy string          `json:"cancelledBy,omitempty"`
}

// InstanceState is the resource instance lifecycle (plan §5.11).
type InstanceState string

const (
	InstanceStatePending   InstanceState = "pending"
	InstanceStateDeploying InstanceState = "deploying"
	InstanceStateRunning   InstanceState = "running"
	InstanceStateUpgrading InstanceState = "upgrading"
	InstanceStateDegraded  InstanceState = "degraded"
	InstanceStateFailed    InstanceState = "failed"
	InstanceStateDeleting  InstanceState = "deleting"
)

// ResourceRef identifies the cluster resource backing an instance, as
// reported by the agent in status-update events.
type ResourceRef struct {
	Group     string `json:"group,omitempty"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// ResourceInstance is one deployed catalog item on a cluster (plan §5.9).
type ResourceInstance struct {
	ID             string          `json:"id"`
	OrgID          string          `json:"orgId"`
	ClusterID      string          `json:"clusterId"`
	CatalogItemID  string          `json:"catalogItemId"`
	Version        string          `json:"version"`
	OwnerTeam      string          `json:"ownerTeam"`
	Spec           json.RawMessage `json:"spec"`
	ResourceRef    ResourceRef     `json:"resourceRef"`
	Health         string          `json:"health"`
	SyncState      string          `json:"syncState,omitempty"`
	StatusMessage  string          `json:"statusMessage,omitempty"`
	State          InstanceState   `json:"state"`
	ManagementMode ManagementMode  `json:"managementMode"`
	CommitSHA      string          `json:"commitSha,omitempty"`
	PRURL          string          `json:"prUrl,omitempty"`
	Generation     int             `json:"generation"`
	CreatedAt      time.Time       `json:"createdAt"`
	UpdatedAt      time.Time       `json:"updatedAt"`
}

// CommitPolicy selects direct commit vs pull request (plan §11.2).
type CommitPolicy string

const (
	CommitPolicyDirect      CommitPolicy = "direct"
	CommitPolicyPullRequest CommitPolicy = "pull_request"
)

// TenantGitConfig is the per-tenant git target + policy for the
// platform-owned <tenant>-inari-state repository.
type TenantGitConfig struct {
	OrgID        string       `json:"orgId"`
	Repo         string       `json:"repo"`
	CommitPolicy CommitPolicy `json:"commitPolicy"`
	BaseBranch   string       `json:"baseBranch"`
}

// CatalogItemPayload is the outbox payload for EventCatalogItemUpserted.
type CatalogItemPayload struct {
	OrgID  string `json:"orgId"` // owning org; empty for global curated/platform items
	ItemID string `json:"itemId"`
	Source string `json:"source"`
}

// ApprovalPayload is the outbox payload for approval events.
type ApprovalPayload struct {
	OrgID      string `json:"orgId"`
	ApprovalID string `json:"approvalId"`
	ItemID     string `json:"itemId"`
	State      string `json:"state"`
}

// DeployRequestedPayload is the outbox payload for EventDeployRequested.
type DeployRequestedPayload struct {
	OrgID      string `json:"orgId"`
	InstanceID string `json:"instanceId"`
	ItemID     string `json:"itemId"`
	ClusterID  string `json:"clusterId"`
	Version    string `json:"version"`
	CommitSHA  string `json:"commitSha,omitempty"`
	PRURL      string `json:"prUrl,omitempty"`
}

// InstancePayload is the outbox payload for instance lifecycle events.
type InstancePayload struct {
	OrgID      string `json:"orgId"`
	InstanceID string `json:"instanceId"`
	ItemID     string `json:"itemId"`
	ClusterID  string `json:"clusterId"`
	Version    string `json:"version,omitempty"`
	Health     string `json:"health,omitempty"`
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

// Cloud account states (plan §5.7).
const (
	CloudAccountStatePendingValidation = "pending_validation"
	CloudAccountStateActive            = "active"
	CloudAccountStateInvalid           = "invalid"
	CloudAccountStateRevoked           = "revoked"
)

// Cloud account run contexts (§5.7): where Crossplane materializes the
// per-account ProviderConfig.
const (
	CloudAccountRunContextTenant   = "tenant"
	CloudAccountRunContextPlatform = "platform"
)

// CloudAccount is a registered cloud account (AWS first, plan §5.7). It
// stores ONLY account ID, role ARN, external ID and issuer metadata — never
// keys. Revocation is tenant-side: the tenant deletes the IAM role.
//
// This entity is a public contract: the Tenant Zone Factory (M3-W2) builds
// on it (management-scope accounts, trust bootstrap). Keep the API stable.
type CloudAccount struct {
	ID            string     `json:"id"`
	OrgID         string     `json:"orgId"`
	Provider      string     `json:"provider"` // "aws"
	AccountID     string     `json:"accountId"`
	RoleARN       string     `json:"roleArn"`
	ExternalID    string     `json:"externalId,omitempty"`
	IssuerURL     string     `json:"issuerUrl,omitempty"`
	RunContext    string     `json:"runContext"` // tenant | platform
	State         string     `json:"state"`
	ValidatedAt   *time.Time `json:"validatedAt,omitempty"`
	ValidationErr string     `json:"validationError,omitempty"`
	CreatedBy     string     `json:"createdBy,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
}

// CloudAccountPayload is the outbox payload for cloud account events.
type CloudAccountPayload struct {
	OrgID     string `json:"orgId"`
	AccountID string `json:"accountId"` // cloud_accounts.id
	AWSAcct   string `json:"awsAccountId,omitempty"`
	State     string `json:"state,omitempty"`
}

// Policy targets / engines (plan §5.11).
const (
	PolicyTargetRequest = "request"
	PolicyTargetRender  = "render"
	PolicyEngineRego    = "rego"
)

// Policy is one versioned policy document evaluated at request-time
// (pre-flight) or render-time (manifest checks).
type Policy struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"orgId,omitempty"` // empty = platform-global
	Name      string    `json:"name"`
	Target    string    `json:"target"`
	Engine    string    `json:"engine"`
	Source    string    `json:"source"`
	Enabled   bool      `json:"enabled"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// PolicyViolation is one failed rule with reason + remediation (§5.11:
// developers see why and what to change, not just a denial).
type PolicyViolation struct {
	Rule        string `json:"rule"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation"`
	Exempted    bool   `json:"exempted,omitempty"`
}

// PolicyDecision is the outcome of a policy evaluation.
type PolicyDecision struct {
	Allow      bool              `json:"allow"`
	Warnings   []PolicyViolation `json:"warnings,omitempty"`
	Violations []PolicyViolation `json:"violations,omitempty"`
}

// ClusterSet is a label-selector grouping of clusters — the targeting unit
// for fleet-wide operations (§5.11).
type ClusterSet struct {
	ID            string            `json:"id"`
	OrgID         string            `json:"orgId"`
	Name          string            `json:"name"`
	LabelSelector map[string]string `json:"labelSelector"`
	CreatedAt     time.Time         `json:"createdAt"`
}

// Policy pack engines (§5.11).
const (
	PolicyPackEngineKyverno = "kyverno"
	PolicyPackEngineCELVAP  = "cel-vap"
)

// PolicyPack is a versioned bundle of in-cluster admission policies
// (Kyverno or CEL ValidatingAdmissionPolicies) distributed to ClusterSets.
type PolicyPack struct {
	ID         string          `json:"id"`
	OrgID      string          `json:"orgId,omitempty"` // empty = platform-global
	Name       string          `json:"name"`
	Engine     string          `json:"engine"`
	OCIRef     string          `json:"ociRef,omitempty"`
	Version    string          `json:"version"`
	Parameters json.RawMessage `json:"parameters,omitempty"`
	Manifests  json.RawMessage `json:"manifests"` // array of YAML/JSON documents
	CreatedAt  time.Time       `json:"createdAt"`
}

// Policy assignment targets.
const (
	PolicyTargetClusterSet = "clusterset"
	PolicyTargetTenant     = "tenant"
	PolicyTargetCluster    = "cluster"
)

// PolicyAssignment binds a pack to a ClusterSet / tenant / cluster.
type PolicyAssignment struct {
	ID         string    `json:"id"`
	PackID     string    `json:"packId"`
	TargetType string    `json:"targetType"`
	TargetID   string    `json:"targetId"`
	State      string    `json:"state"`
	CreatedAt  time.Time `json:"createdAt"`
}

// PolicyPackAssignedPayload is the outbox payload for pack assignment.
type PolicyPackAssignedPayload struct {
	OrgID        string `json:"orgId"`
	PackID       string `json:"packId"`
	AssignmentID string `json:"assignmentId"`
	TargetType   string `json:"targetType"`
	TargetID     string `json:"targetId"`
}

// ClusterSetPayload is the outbox payload for cluster set lifecycle events.
type ClusterSetPayload struct {
	OrgID        string `json:"orgId"`
	ClusterSetID string `json:"clusterSetId"`
}

// Exemption states.
const (
	ExemptionStatePending  = "pending"
	ExemptionStateApproved = "approved"
	ExemptionStateRejected = "rejected"
	ExemptionStateExpired  = "expired"
)

// Exemption is a time-boxed, approval-gated policy waiver (§5.11).
type Exemption struct {
	ID         string          `json:"id"`
	OrgID      string          `json:"orgId"`
	PolicyID   string          `json:"policyId"`
	Scope      json.RawMessage `json:"scope"`
	Reason     string          `json:"reason"`
	State      string          `json:"state"`
	ExpiresAt  time.Time       `json:"expiresAt"`
	ApprovedBy string          `json:"approvedBy,omitempty"`
	CreatedBy  string          `json:"createdBy,omitempty"`
	CreatedAt  time.Time       `json:"createdAt"`
}

// ExemptionPayload is the outbox payload for exemption events.
type ExemptionPayload struct {
	OrgID       string `json:"orgId"`
	ExemptionID string `json:"exemptionId"`
	PolicyID    string `json:"policyId"`
	State       string `json:"state"`
}

// Notification endpoint kinds (§5.2 v1: Slack + generic webhook).
const (
	NotificationKindSlack   = "slack"
	NotificationKindWebhook = "webhook"
)

// NotificationEndpoint is a tenant-configured delivery target. The Secret
// holds an HMAC signing key for webhook kind (never returned by the API).
type NotificationEndpoint struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"orgId"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	URL       string    `json:"url"`
	Secret    string    `json:"-"`
	Events    []string  `json:"events"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"createdAt"`
}

// Notification delivery states.
const (
	DeliveryStatusPending   = "pending"
	DeliveryStatusDelivered = "delivered"
	DeliveryStatusFailed    = "failed"
)

// NotificationDelivery records one attempted delivery for retry/audit.
type NotificationDelivery struct {
	ID          string          `json:"id"`
	EndpointID  string          `json:"endpointId"`
	EventType   string          `json:"eventType"`
	Payload     json.RawMessage `json:"payload"`
	Status      string          `json:"status"`
	Attempts    int             `json:"attempts"`
	LastError   string          `json:"lastError,omitempty"`
	CreatedAt   time.Time       `json:"createdAt"`
	DeliveredAt *time.Time      `json:"deliveredAt,omitempty"`
}

// Tenant Zone lifecycle (plan §5.12): the resumable, idempotent vending
// state machine. Long-running AWS operations are tracked as step
// sub-resources with status; failures route to manual_intervention (§10).
type TenantZoneState string

const (
	ZoneStateRequested                   TenantZoneState = "requested"
	ZoneStatePendingApproval             TenantZoneState = "pending_approval"
	ZoneStateProvisioning                TenantZoneState = "provisioning"
	ZoneStateWiring                      TenantZoneState = "wiring"
	ZoneStateActive                      TenantZoneState = "active"
	ZoneStateFailed                      TenantZoneState = "failed"
	ZoneStateManualIntervention          TenantZoneState = "manual_intervention"
	ZoneStateDecommissionPendingApproval TenantZoneState = "decommission_pending_approval"
	ZoneStateCordoning                   TenantZoneState = "cordoning"
	ZoneStateDraining                    TenantZoneState = "draining"
	ZoneStateDecommissioning             TenantZoneState = "decommissioning"
	ZoneStateClosed                      TenantZoneState = "closed"
)

// Provisioning step names (in order) and their decommission mirrors.
const (
	ZoneStepPreflight      = "preflight"
	ZoneStepAccountVend    = "account_vend"
	ZoneStepTrustBootstrap = "trust_bootstrap"
	ZoneStepEKSProvision   = "eks_provision"
	ZoneStepInariWiring    = "inari_wiring"

	ZoneStepCordon         = "cordon"
	ZoneStepDrain          = "drain"
	ZoneStepEKSDelete      = "eks_delete"
	ZoneStepAccountClose   = "account_close"
	ZoneStepIdentityRevoke = "identity_revoke"
	ZoneStepAuditArchive   = "audit_archive"
)

// TenantZone step statuses.
const (
	ZoneStepPending   = "pending"
	ZoneStepRunning   = "running"
	ZoneStepWaiting   = "waiting" // async AWS/MR operation in flight
	ZoneStepSucceeded = "succeeded"
	ZoneStepFailed    = "failed"
	ZoneStepSkipped   = "skipped"
)

// TenantZone is one vended (or in-progress) tenant zone (plan §5.9, §5.12).
type TenantZone struct {
	ID                  string            `json:"id"`
	Slug                string            `json:"slug"`
	DisplayName         string            `json:"displayName"`
	OwnerOrgID          string            `json:"ownerOrgId"`      // org owning the management account (platform org)
	OrgID               string            `json:"orgId,omitempty"` // wired Keycloak org; empty until inari_wiring
	OUID                string            `json:"ouId"`
	Region              string            `json:"region"`
	Tier                string            `json:"tier"`
	State               TenantZoneState   `json:"state"`
	ManagementAccountID string            `json:"managementAccountId"` // cloud_accounts.id (scope: management)
	AWSAccountID        string            `json:"awsAccountId,omitempty"`
	ClusterID           string            `json:"clusterId,omitempty"`
	CloudAccountID      string            `json:"cloudAccountId,omitempty"`
	KeycloakOrgID       string            `json:"keycloakOrgId,omitempty"`
	GitRepo             string            `json:"gitRepo,omitempty"`
	Tags                map[string]string `json:"tags,omitempty"` // mandatory cost/allocation tags (§5.12)
	Error               string            `json:"error,omitempty"`
	CreatedBy           string            `json:"createdBy"`
	CreatedAt           time.Time         `json:"createdAt"`
	UpdatedAt           time.Time         `json:"updatedAt"`
}

// TenantZoneStep tracks one sub-resource of the vending/decommission flow
// (plan §5.12 "long-running AWS operations tracked as sub-resources with
// status"). ExternalRef persists the async operation handle (CreateAccount
// request ID, MR ref) so restarts resume polling instead of re-creating.
type TenantZoneStep struct {
	ZoneID      string          `json:"zoneId"`
	Step        string          `json:"step"`
	Status      string          `json:"status"`
	ExternalRef string          `json:"externalRef,omitempty"`
	Detail      json.RawMessage `json:"detail,omitempty"`
	Attempts    int             `json:"attempts"`
	UpdatedAt   time.Time       `json:"updatedAt"`
}

// Tenant zone outbox events.
const (
	EventTenantZoneRequested             = "tenant_zone.requested"
	EventTenantZoneProvisioning          = "tenant_zone.provisioning"
	EventTenantZoneStepUpdated           = "tenant_zone.step_updated"
	EventTenantZoneActive                = "tenant_zone.active"
	EventTenantZoneFailed                = "tenant_zone.failed"
	EventTenantZoneDecommissionRequested = "tenant_zone.decommission_requested"
	EventTenantZoneDecommissionDenied    = "tenant_zone.decommission_denied"
	EventTenantZoneClosed                = "tenant_zone.closed"
)

// TenantZonePayload is the outbox payload for tenant zone events. ZoneOrgID
// is the zone's own (wired) organization, set once known; OrgID is the
// owning platform org the event is scoped to.
type TenantZonePayload struct {
	OrgID      string `json:"orgId,omitempty"`
	ZoneOrgID  string `json:"zoneOrgId,omitempty"`
	ZoneID     string `json:"zoneId"`
	Slug       string `json:"slug"`
	State      string `json:"state,omitempty"`
	Step       string `json:"step,omitempty"`
	StepStatus string `json:"stepStatus,omitempty"`
}
