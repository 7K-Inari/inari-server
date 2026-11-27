// Package planlimits provides generic plan-limit lookup and metering seams.
// Enforcement policy and external plan interpretation live elsewhere.
package planlimits

import (
	"context"
	"errors"

	provisioning "github.com/7K-Inari/inari-api/contract/provisioning/v1"
)

type Limits = provisioning.Limits

type PlanLimitsProvider interface {
	PlanLimits(ctx context.Context, tenantID string) (Limits, error)
}

var (
	ErrLimitsNotFound  = errors.New("planlimits: limits not found")
	ErrInvalidTenantID = errors.New("planlimits: invalid tenant id")
)

type UnlimitedProvider struct{}

func (UnlimitedProvider) PlanLimits(context.Context, string) (Limits, error) {
	return Limits{AllFeatures: true}, nil
}
