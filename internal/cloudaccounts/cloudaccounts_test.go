package cloudaccounts

import (
	"testing"
)

func TestValidateRegisterInput(t *testing.T) {
	valid := RegisterInput{
		Provider:  "aws",
		AccountID: "123456789012",
		RoleARN:   "arn:aws:iam::123456789012:role/inari-crossplane",
	}
	cases := []struct {
		name    string
		mutate  func(*RegisterInput)
		wantErr bool
	}{
		{"valid", func(in *RegisterInput) {}, false},
		{"valid with path and external id", func(in *RegisterInput) {
			in.RoleARN = "arn:aws:iam::123456789012:role/team/inari-crossplane"
			in.ExternalID = "ext-123"
		}, false},
		{"empty provider defaults to aws", func(in *RegisterInput) { in.Provider = "" }, false},
		{"bad provider", func(in *RegisterInput) { in.Provider = "gcp" }, true},
		{"account id too short", func(in *RegisterInput) { in.AccountID = "12345" }, true},
		{"account id not numeric", func(in *RegisterInput) { in.AccountID = "12345678901a" }, true},
		{"arn wrong partition", func(in *RegisterInput) { in.RoleARN = "arn:aws-us-gov:iam::123456789012:role/x" }, true},
		{"arn not iam", func(in *RegisterInput) { in.RoleARN = "arn:aws:s3:::bucket" }, true},
		{"arn not role", func(in *RegisterInput) { in.RoleARN = "arn:aws:iam::123456789012:user/bob" }, true},
		{"arn missing account", func(in *RegisterInput) { in.RoleARN = "arn:aws:iam:::role/x" }, true},
		{"arn malformed", func(in *RegisterInput) { in.RoleARN = "not-an-arn" }, true},
		{"bad run context", func(in *RegisterInput) { in.RunContext = "somewhere" }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := valid
			tc.mutate(&in)
			err := validateRegisterInput(&in)
			if tc.wantErr && err == nil {
				t.Fatalf("want error, got nil (input: %+v)", in)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("want no error, got %v", err)
			}
		})
	}
}

func TestValidateRegisterInputDefaults(t *testing.T) {
	in := RegisterInput{AccountID: "123456789012", RoleARN: "arn:aws:iam::123456789012:role/x"}
	if err := validateRegisterInput(&in); err != nil {
		t.Fatal(err)
	}
	if in.Provider != "aws" {
		t.Errorf("provider = %q, want aws", in.Provider)
	}
	if in.RunContext != "tenant" {
		t.Errorf("runContext = %q, want tenant", in.RunContext)
	}
}
