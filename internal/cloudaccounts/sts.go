package cloudaccounts

import (
	"context"
	"errors"
)

// ErrValidationUnavailable is returned when the platform has no AWS
// credentials/token source to perform the AssumeRole dry-run; the account
// stays pending_validation.
var ErrValidationUnavailable = errors.New("sts validation unavailable")

// STSValidator performs the trust-bootstrap dry-run (plan §5.7): prove the
// platform identity can assume the tenant-provided role. It NEVER stores
// any credentials.
type STSValidator interface {
	// AssumeRoleDryRun assumes roleARN (with externalID when set) using the
	// platform's ambient identity. issuerURL carries OIDC metadata for
	// future web-identity exchanges. Returns nil on success,
	// ErrValidationUnavailable when no token source is configured, or the
	// underlying AWS error on denial.
	AssumeRoleDryRun(ctx context.Context, roleARN, externalID, issuerURL string) error
}

// DisabledValidator is used when the platform has no AWS token source
// configured (e.g. no IRSA on the platform cluster). Validation is
// unavailable; accounts stay pending_validation.
type DisabledValidator struct{}

// AssumeRoleDryRun implements STSValidator.
func (DisabledValidator) AssumeRoleDryRun(context.Context, string, string, string) error {
	return ErrValidationUnavailable
}
