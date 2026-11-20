package extensionhost

import (
	"net/http"
	"testing"

	"github.com/danielgtaylor/huma/v2"

	extensionv1 "github.com/7K-Inari/inari-api/contract/extension/v1"
)

func TestMapErrContractViolationIs422(t *testing.T) {
	err := mapErr(extensionv1.NewContractError(extensionv1.CodeContractUnsupported, "spec.contracts.backend", "unsupported"))
	status, ok := err.(huma.StatusError)
	if !ok || status.GetStatus() != http.StatusUnprocessableEntity {
		t.Fatalf("mapErr = %#v, want huma 422", err)
	}
}
