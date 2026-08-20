// AWS SDK-backed implementations of the TZF seams. Used only when
// INARI_TZF_AWS_MODE=aws and the platform has ambient credentials (IRSA on
// the platform cluster); the management role behind them is least-
// privilege: organizations:CreateAccount/TagResource/
// DescribeCreateAccountStatus (+ CloseAccount) only (plan §5.12).
package tenantzonefactory

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// AWSOrganizations implements Organizations against the AWS SDK using the
// platform's ambient identity (credentials in-memory only — §5.10).
type AWSOrganizations struct {
	org *organizations.Client
}

// NewAWSOrganizations loads the default AWS config (IRSA env on the
// platform cluster) and returns the SDK-backed seam.
func NewAWSOrganizations(ctx context.Context) (*AWSOrganizations, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("tzf: load aws config: %w", err)
	}
	if _, err := cfg.Credentials.Retrieve(ctx); err != nil {
		return nil, fmt.Errorf("tzf: no platform aws credentials: %w", err)
	}
	return &AWSOrganizations{org: organizations.NewFromConfig(cfg)}, nil
}

// CreateAccount implements Organizations. AWS CreateAccount has no native
// idempotency token, so in-flight requests are matched by account name
// first (idempotencyToken is the zone ID, unused by the AWS impl) —
// concurrent/duplicate vends collapse onto one request (§10).
func (a *AWSOrganizations) CreateAccount(ctx context.Context, name, email, ouID string, tags map[string]string, idempotencyToken string) (*CreateAccountResult, error) {
	p := organizations.NewListCreateAccountStatusPaginator(a.org, &organizations.ListCreateAccountStatusInput{
		States: []orgtypes.CreateAccountState{orgtypes.CreateAccountStateInProgress},
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("tzf: list in-flight create requests: %w", err)
		}
		for _, st := range page.CreateAccountStatuses {
			if aws.ToString(st.AccountName) == name {
				return &CreateAccountResult{RequestID: aws.ToString(st.Id)}, nil
			}
		}
	}
	in := &organizations.CreateAccountInput{
		AccountName: aws.String(name),
		Email:       aws.String(email),
	}
	for k, v := range tags {
		in.Tags = append(in.Tags, orgtypes.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	out, err := a.org.CreateAccount(ctx, in)
	if err != nil {
		return nil, err
	}
	return &CreateAccountResult{RequestID: aws.ToString(out.CreateAccountStatus.Id)}, nil
}

// MoveAccount implements Organizations.
func (a *AWSOrganizations) MoveAccount(ctx context.Context, accountID, ouID string) error {
	root, err := a.org.ListRoots(ctx, &organizations.ListRootsInput{})
	if err != nil {
		return fmt.Errorf("tzf: list roots: %w", err)
	}
	if len(root.Roots) == 0 {
		return fmt.Errorf("tzf: no organization root found")
	}
	if _, err := a.org.MoveAccount(ctx, &organizations.MoveAccountInput{
		AccountId:           aws.String(accountID),
		SourceParentId:      root.Roots[0].Id,
		DestinationParentId: aws.String(ouID),
	}); err != nil {
		return fmt.Errorf("tzf: move account to %s: %w", ouID, err)
	}
	return nil
}

// DescribeCreateAccountStatus implements Organizations.
func (a *AWSOrganizations) DescribeCreateAccountStatus(ctx context.Context, requestID string) (*AccountStatus, error) {
	out, err := a.org.DescribeCreateAccountStatus(ctx, &organizations.DescribeCreateAccountStatusInput{
		CreateAccountRequestId: aws.String(requestID),
	})
	if err != nil {
		return nil, err
	}
	st := out.CreateAccountStatus
	s := &AccountStatus{AccountID: aws.ToString(st.AccountId)}
	switch st.State {
	case orgtypes.CreateAccountStateSucceeded:
		s.State = "SUCCEEDED"
	case orgtypes.CreateAccountStateFailed:
		s.State = "FAILED"
		s.FailureReason = string(st.FailureReason)
	default:
		s.State = "IN_PROGRESS"
	}
	return s, nil
}

// CloseAccount implements Organizations.
func (a *AWSOrganizations) CloseAccount(ctx context.Context, accountID string) (*CreateAccountResult, error) {
	if _, err := a.org.CloseAccount(ctx, &organizations.CloseAccountInput{
		AccountId: aws.String(accountID),
	}); err != nil {
		return nil, err
	}
	// CloseAccount is synchronous-accepted; track it as a completed request.
	return &CreateAccountResult{RequestID: "close-" + accountID}, nil
}

// CountAccounts implements Organizations.
func (a *AWSOrganizations) CountAccounts(ctx context.Context, ouID string) (int, error) {
	count := 0
	p := organizations.NewListAccountsForParentPaginator(a.org, &organizations.ListAccountsForParentInput{
		ParentId: aws.String(ouID),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return 0, err
		}
		count += len(page.Accounts)
	}
	return count, nil
}

// AWSTrustBootstrap implements TrustBootstrap: assumes the auto-created
// OrganizationAccountAccessRole in the vended account and creates the
// standard OIDC web-identity role (same contract as BYO onboarding §5.7).
type AWSTrustBootstrap struct {
	sts *sts.Client
}

// NewAWSTrustBootstrap loads the default AWS config for the management
// identity.
func NewAWSTrustBootstrap(ctx context.Context) (*AWSTrustBootstrap, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("tzf: load aws config: %w", err)
	}
	return &AWSTrustBootstrap{sts: sts.NewFromConfig(cfg)}, nil
}

// EnsureOIDCRole implements TrustBootstrap (idempotent by role name). The
// OIDC provider for the platform issuer is created first — without it the
// role's federated trust can never be used.
func (b *AWSTrustBootstrap) EnsureOIDCRole(ctx context.Context, accountID, issuerURL, roleName string) (string, error) {
	if roleName == "" {
		roleName = "inari-onboarding"
	}
	mgmtCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return "", err
	}
	creds := stscreds.NewAssumeRoleProvider(b.sts, fmt.Sprintf("arn:aws:iam::%s:role/OrganizationAccountAccessRole", accountID))
	mgmtCfg.Credentials = aws.NewCredentialsCache(creds)
	iamc := iam.NewFromConfig(mgmtCfg)
	arn := fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, roleName)
	issuer := trimScheme(issuerURL)
	providerARN := fmt.Sprintf("arn:aws:iam::%s:oidc-provider/%s", accountID, issuer)
	if _, err := iamc.GetOpenIDConnectProvider(ctx, &iam.GetOpenIDConnectProviderInput{
		OpenIDConnectProviderArn: aws.String(providerARN),
	}); err != nil {
		if !isNoSuchEntity(err) {
			return "", fmt.Errorf("tzf: get oidc provider in %s: %w", accountID, err)
		}
		if _, err := iamc.CreateOpenIDConnectProvider(ctx, &iam.CreateOpenIDConnectProviderInput{
			Url:          aws.String(issuerURL),
			ClientIDList: []string{"sts.amazonaws.com"},
			Tags:         []iamtypes.Tag{{Key: aws.String("managed-by"), Value: aws.String("inari")}},
		}); err != nil {
			return "", fmt.Errorf("tzf: create oidc provider in %s: %w", accountID, err)
		}
	}
	if _, err := iamc.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(roleName)}); err == nil {
		return arn, nil
	} else if !isNoSuchEntity(err) {
		return "", fmt.Errorf("tzf: get role %s in %s: %w", roleName, accountID, err)
	}
	trust := fmt.Sprintf(`{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "%s"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {"StringEquals": {"%s:aud": "sts.amazonaws.com"}}
  }]
}`, providerARN, issuer)
	if _, err := iamc.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName:                 aws.String(roleName),
		AssumeRolePolicyDocument: aws.String(trust),
		Description:              aws.String("Inari OIDC web-identity onboarding role (plan §5.7)"),
		Tags:                     []iamtypes.Tag{{Key: aws.String("managed-by"), Value: aws.String("inari")}},
	}); err != nil {
		return "", fmt.Errorf("tzf: create oidc role in %s: %w", accountID, err)
	}
	return arn, nil
}

// isNoSuchEntity reports whether err is IAM's NoSuchEntity (as opposed to
// throttling/access-denied, which must NOT be treated as "does not exist").
func isNoSuchEntity(err error) bool {
	var nse *iamtypes.NoSuchEntityException
	return errors.As(err, &nse)
}

func trimScheme(u string) string {
	const p = "https://"
	if len(u) > len(p) && u[:len(p)] == p {
		return u[len(p):]
	}
	return u
}
