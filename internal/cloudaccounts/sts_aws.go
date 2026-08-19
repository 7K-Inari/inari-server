package cloudaccounts

// AWS SDK-backed STS validator. Used when the platform has an ambient AWS
// identity (e.g. IRSA via AWS_WEB_IDENTITY_TOKEN_FILE on the platform
// cluster); otherwise NewSTSValidator returns DisabledValidator.

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// awsSTSValidator performs the dry-run with the platform's ambient AWS
// identity (e.g. IRSA via AWS_WEB_IDENTITY_TOKEN_FILE on the platform
// cluster). Credentials are used in-memory only — never stored.
type awsSTSValidator struct{}

// NewSTSValidator returns the AWS SDK validator when a web-identity token
// source is configured on the platform cluster, else a DisabledValidator.
func NewSTSValidator() STSValidator {
	if os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE") == "" {
		return DisabledValidator{}
	}
	return awsSTSValidator{}
}

// AssumeRoleDryRun implements STSValidator.
func (awsSTSValidator) AssumeRoleDryRun(ctx context.Context, roleARN, externalID, issuerURL string) error {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("cloudaccounts: load aws config: %w", err)
	}
	if _, err := cfg.Credentials.Retrieve(ctx); err != nil {
		return fmt.Errorf("cloudaccounts: no platform credentials: %w", ErrValidationUnavailable)
	}
	in := &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleARN),
		RoleSessionName: aws.String("inari-validation-dry-run"),
		DurationSeconds: aws.Int32(900),
	}
	if externalID != "" {
		in.ExternalId = aws.String(externalID)
	}
	if _, err := sts.NewFromConfig(cfg).AssumeRole(ctx, in); err != nil {
		return fmt.Errorf("cloudaccounts: assume role dry-run: %w", err)
	}
	return nil
}
