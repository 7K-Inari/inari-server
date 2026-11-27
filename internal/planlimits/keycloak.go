package planlimits

import (
	"context"
	"fmt"
	"strings"

	provisioning "github.com/7K-Inari/inari-api/contract/provisioning/v1"
	planlimitsv1 "github.com/7K-Inari/inari-api/gen/go/inari/planlimits/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const KeycloakPlanLimitsAttribute = "inari.plan.limits.v1"

type OrganizationAttributesReader interface {
	OrganizationAttributes(ctx context.Context, keycloakOrgID string) (map[string][]string, error)
}

type KeycloakProvider struct {
	reader OrganizationAttributesReader
}

func NewKeycloakProvider(reader OrganizationAttributesReader) *KeycloakProvider {
	return &KeycloakProvider{reader: reader}
}

func (p *KeycloakProvider) PlanLimits(ctx context.Context, tenantID string) (Limits, error) {
	keycloakOrgID := strings.TrimPrefix(tenantID, "org:")
	if p == nil || p.reader == nil || keycloakOrgID == "" || keycloakOrgID == tenantID {
		return Limits{}, ErrInvalidTenantID
	}
	attributes, err := p.reader.OrganizationAttributes(ctx, keycloakOrgID)
	if err != nil {
		return Limits{}, err
	}
	values := attributes[KeycloakPlanLimitsAttribute]
	if len(values) == 0 || strings.TrimSpace(values[0]) == "" {
		return Limits{}, ErrLimitsNotFound
	}
	var wire planlimitsv1.PlanLimits
	if err := protojson.Unmarshal([]byte(values[0]), &wire); err != nil {
		return Limits{}, fmt.Errorf("planlimits: decode limits: %w", err)
	}
	limits, err := provisioning.LimitsFromProto(&wire)
	if err != nil {
		return Limits{}, err
	}
	return *limits, nil
}
