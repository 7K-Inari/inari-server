package cloudaccounts

import (
	"strings"
	"testing"
)

func TestValidateRegisterInputRejectsARNAccountMismatch(t *testing.T) {
	in := RegisterInput{
		AccountID: "111111111111",
		RoleARN:   "arn:aws:iam::222222222222:role/inari-crossplane",
	}
	if err := validateRegisterInput(&in); err == nil {
		t.Fatal("account ID and role ARN account mismatch must be rejected")
	}
}

func TestValidateRegisterInputIssuerAndExternalID(t *testing.T) {
	base := RegisterInput{AccountID: "123456789012", RoleARN: "arn:aws:iam::123456789012:role/x"}

	in := base
	in.IssuerURL = "http://issuer.example.com"
	if err := validateRegisterInput(&in); err == nil {
		t.Fatal("non-https issuer URL must be rejected")
	}

	in = base
	in.IssuerURL = "https://issuer.example.com"
	if err := validateRegisterInput(&in); err != nil {
		t.Fatalf("https issuer URL should pass: %v", err)
	}

	in = base
	in.ExternalID = strings.Repeat("a", 1225)
	if err := validateRegisterInput(&in); err == nil {
		t.Fatal("external ID over 1224 chars must be rejected")
	}
}
