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
	ID           string    `json:"id"`
	Slug         string    `json:"slug"`
	DisplayName  string    `json:"displayName"`
	KeycloakOrgID string   `json:"keycloakOrgId"`
	CreatedAt    time.Time `json:"createdAt"`
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
)

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
