package cloudaccounts

import "testing"

func TestValidateRegisterInputRejectsARNAccountMismatch(t *testing.T) {
	in := RegisterInput{
		AccountID: "111111111111",
		RoleARN:   "arn:aws:iam::222222222222:role/inari-crossplane",
	}
	if err := validateRegisterInput(&in); err == nil {
		t.Fatal("account ID and role ARN account mismatch must be rejected")
	}
}
