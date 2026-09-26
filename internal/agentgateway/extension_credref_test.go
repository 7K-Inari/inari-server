package agentgateway

import (
	"strings"
	"testing"
)

func TestValidateUserCredentialRef(t *testing.T) {
	valid := []string{
		"ucr_01JABCXYZ",
		"sess:user-1:argocd",
		"ref/tenant-acme/abc-123",
		"a",
		strings.Repeat("x", userCredentialRefMaxLen),
	}
	for _, ref := range valid {
		if err := validateUserCredentialRef(ref); err != nil {
			t.Errorf("ref %q: unexpected error %v", ref, err)
		}
	}

	invalid := map[string]string{
		"empty":          "",
		"too long":       strings.Repeat("x", userCredentialRefMaxLen+1),
		"spaces":         "ref with space",
		"jwt":            "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.c2lnbmF0dXJl",
		"jwt empty sig":  "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.",
		"bearer literal": "Bearer abc",
	}
	for name, ref := range invalid {
		if err := validateUserCredentialRef(ref); err == nil {
			t.Errorf("%s (%q): want error", name, ref)
		}
	}
}
