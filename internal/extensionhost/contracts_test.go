package extensionhost

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	extensionv1 "github.com/7K-Inari/inari-api/contract/extension/v1"
)

func TestContractPolicyNormalizeAndDefensiveCopies(t *testing.T) {
	policy, err := NewContractPolicy(
		[]string{" inari.plugin.v2 ", "inari.plugin.v1"},
		[]string{"inari.ui.v2", "inari.ui.v1"},
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := policy.PluginContracts(); !reflect.DeepEqual(got, []string{"inari.plugin.v1", "inari.plugin.v2"}) {
		t.Fatalf("plugin contracts = %v", got)
	}
	if got := policy.UIHostAPIs(); !reflect.DeepEqual(got, []string{"inari.ui.v1", "inari.ui.v2"}) {
		t.Fatalf("UI host APIs = %v", got)
	}
	plugins := policy.PluginContracts()
	plugins[0] = "mutated"
	if policy.PluginContracts()[0] != "inari.plugin.v1" {
		t.Fatal("policy slice was mutable")
	}
	if !policy.Required() {
		t.Fatal("required flag lost")
	}
	for _, tc := range []struct{ plugins, uis []string }{
		{nil, []string{extensionv1.UIHostAPIV1}},
		{[]string{extensionv1.BackendContractV1}, nil},
		{[]string{"bad"}, []string{extensionv1.UIHostAPIV1}},
		{[]string{extensionv1.BackendContractV1, extensionv1.BackendContractV1}, []string{extensionv1.UIHostAPIV1}},
	} {
		if _, err := NewContractPolicy(tc.plugins, tc.uis, false); err == nil {
			t.Fatalf("NewContractPolicy(%v, %v) accepted invalid input", tc.plugins, tc.uis)
		}
	}
}

func TestContractPolicyBackendValidation(t *testing.T) {
	policy := DefaultContractPolicy()
	legacy, err := policy.ValidateBackendManifest(json.RawMessage(`{"auth":{}}`))
	if err != nil || legacy != nil {
		t.Fatalf("legacy = %#v, %v", legacy, err)
	}
	valid, err := policy.ValidateBackendManifest(json.RawMessage(`{"contracts":{"backend":["inari.plugin.v1","inari.plugin.v2"]}}`))
	if err != nil || valid == nil || len(valid.Backend) != 2 {
		t.Fatalf("valid = %#v, %v", valid, err)
	}
	for _, tc := range []struct {
		name string
		raw  string
		code extensionv1.ContractErrorCode
	}{
		{"unsupported", `{"contracts":{"backend":["inari.plugin.v2"]}}`, extensionv1.CodeContractUnsupported},
		{"empty", `{"contracts":{"backend":[]}}`, extensionv1.CodeContractMalformed},
		{"missing backend", `{"contracts":{"ui":{"sdk":"^0.1.8","hostApi":"inari.ui.v1"}}}`, extensionv1.CodeContractRequired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := policy.ValidateBackendManifest(json.RawMessage(tc.raw))
			var contractErr *extensionv1.ContractError
			if !errors.As(err, &contractErr) || contractErr.Code != tc.code {
				t.Fatalf("error = %#v, want %s", err, tc.code)
			}
		})
	}
	required, err := NewContractPolicy([]string{extensionv1.BackendContractV1}, []string{extensionv1.UIHostAPIV1}, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := required.ValidateBackendManifest(json.RawMessage(`{}`)); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("required legacy error = %v", err)
	}
}

func TestContractPolicyUIValidation(t *testing.T) {
	policy := DefaultContractPolicy()
	valid := &extensionv1.Contracts{UI: &extensionv1.UIContract{SDK: ">=0.1.8 <2.0.0", HostAPI: extensionv1.UIHostAPIV1}}
	if got, err := policy.ValidateUIContracts(valid); err != nil || got == nil {
		t.Fatalf("valid UI = %#v, %v", got, err)
	}
	for _, tc := range []struct {
		name      string
		contracts *extensionv1.Contracts
		code      extensionv1.ContractErrorCode
	}{
		{"unsupported", &extensionv1.Contracts{UI: &extensionv1.UIContract{SDK: "^0.1.8", HostAPI: "inari.ui.v2"}}, extensionv1.CodeContractUnsupported},
		{"malformed range", &extensionv1.Contracts{UI: &extensionv1.UIContract{SDK: "bad", HostAPI: extensionv1.UIHostAPIV1}}, extensionv1.CodeContractMalformed},
		{"missing UI", &extensionv1.Contracts{Backend: []string{extensionv1.BackendContractV1}}, extensionv1.CodeContractRequired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := policy.ValidateUIContracts(tc.contracts)
			var contractErr *extensionv1.ContractError
			if !errors.As(err, &contractErr) || contractErr.Code != tc.code {
				t.Fatalf("error = %#v, want %s", err, tc.code)
			}
		})
	}
}
