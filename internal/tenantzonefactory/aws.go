// AWS seams for the Tenant Zone Factory (plan §5.12). Narrow interfaces
// over AWS Organizations + the trust bootstrap; the default implementation
// is an in-memory fake (tests/dev), the AWS SDK impl is used only when
// INARI_TZF_AWS_MODE=aws. Credentials are never stored (§5.10).
package tenantzonefactory

import (
	"context"
	"errors"
)

// ErrQuotaExceeded surfaces AWS-side quota/throttle failures (§10).
var ErrQuotaExceeded = errors.New("tzf: aws quota exceeded")

// CreateAccountResult is the handle for the async CreateAccount operation.
type CreateAccountResult struct {
	RequestID string
}

// AccountStatus reports the async CreateAccount/CloseAccount state.
type AccountStatus struct {
	State         string // IN_PROGRESS | SUCCEEDED | FAILED
	AccountID     string // set on SUCCEEDED (CreateAccount)
	FailureReason string
}

// Organizations is the AWS Organizations seam. The management account role
// behind it is least-privilege: organizations:CreateAccount/TagResource/
// DescribeCreateAccountStatus (+ CloseAccount for decommission) only.
type Organizations interface {
	// CreateAccount starts an async account vend in the target OU.
	CreateAccount(ctx context.Context, name, email, ouID string, tags map[string]string) (*CreateAccountResult, error)
	// DescribeCreateAccountStatus polls the async vend/close operation.
	DescribeCreateAccountStatus(ctx context.Context, requestID string) (*AccountStatus, error)
	// CloseAccount starts async account closure (decommission).
	CloseAccount(ctx context.Context, accountID string) (*CreateAccountResult, error)
	// CountAccounts returns the number of accounts under an OU (quota
	// pre-flight, §10).
	CountAccounts(ctx context.Context, ouID string) (int, error)
}

// TrustBootstrap creates the standard OIDC web-identity role in a vended
// account via the auto-created OrganizationAccountAccessRole — the same
// trust contract as BYO onboarding (plan §5.7). Returns the role ARN.
type TrustBootstrap interface {
	EnsureOIDCRole(ctx context.Context, accountID, issuerURL, roleName string) (roleARN string, err error)
}

// Provisioner is the Crossplane seam (plan §5.12 steps 2/4): shaped around
// the managed-resource lifecycle (apply → poll ready → delete) so a
// platform-cluster k8s client implementation drops in without changing the
// state machine. This wave ships the fake only.
type Provisioner interface {
	// ApplyEKSMR materializes the tenant cluster per tier; returns the MR ref.
	ApplyEKSMR(ctx context.Context, accountID, region, tier string) (ref string, err error)
	// MRStatus reports whether the MR is ready.
	MRStatus(ctx context.Context, ref string) (ready bool, err error)
	// DeleteMR deletes the MR (EKS teardown); deletion is async.
	DeleteMR(ctx context.Context, ref string) error
	// MRDeleted reports whether the MR is gone.
	MRDeleted(ctx context.Context, ref string) (bool, error)
}
