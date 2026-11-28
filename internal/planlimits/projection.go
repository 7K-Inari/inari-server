package planlimits

import (
	"context"
	"fmt"
	"strings"

	provisioning "github.com/7K-Inari/inari-api/contract/provisioning/v1"
	planlimitsv1 "github.com/7K-Inari/inari-api/gen/go/inari/planlimits/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// LimitsProjection writes a generic limits document for a tenant.
type LimitsProjection interface {
	PutPlanLimits(ctx context.Context, tenantID string, limits Limits) error
}

// OrganizationAttributesWriter updates an organization's full attribute map.
type OrganizationAttributesWriter interface {
	UpdateOrganizationAttributes(ctx context.Context, keycloakOrgID string, attributes map[string][]string) error
}

// KeycloakProjection projects generic limits into Keycloak attributes while
// preserving every unrelated attribute and skipping equal writes.
type KeycloakProjection struct {
	reader OrganizationAttributesReader
	writer OrganizationAttributesWriter
}

func NewKeycloakProjection(reader OrganizationAttributesReader, writer OrganizationAttributesWriter) *KeycloakProjection {
	return &KeycloakProjection{reader: reader, writer: writer}
}

func (p *KeycloakProjection) PutPlanLimits(ctx context.Context, tenantID string, limits Limits) error {
	keycloakOrgID := strings.TrimPrefix(tenantID, "org:")
	if p == nil || p.reader == nil || p.writer == nil || keycloakOrgID == "" || keycloakOrgID == tenantID {
		return ErrInvalidTenantID
	}
	attributes, err := p.reader.OrganizationAttributes(ctx, keycloakOrgID)
	if err != nil {
		return err
	}
	if attributes == nil {
		attributes = map[string][]string{}
	}
	wire, err := provisioning.LimitsToProto(&limits)
	if err != nil {
		return err
	}
	if values := attributes[KeycloakPlanLimitsAttribute]; len(values) > 0 {
		var existing planlimitsv1.PlanLimits
		if err := protojson.Unmarshal([]byte(values[0]), &existing); err != nil {
			return fmt.Errorf("planlimits: decode existing projection: %w", err)
		}
		if proto.Equal(&existing, wire) {
			return nil
		}
	}
	raw, err := protojson.Marshal(wire)
	if err != nil {
		return err
	}
	attributes[KeycloakPlanLimitsAttribute] = []string{string(raw)}
	return p.writer.UpdateOrganizationAttributes(ctx, keycloakOrgID, attributes)
}
