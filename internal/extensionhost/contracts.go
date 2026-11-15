package extensionhost

import (
	"encoding/json"
	"strings"

	extensionv1 "github.com/7K-Inari/inari-api/contract/extension/v1"
)

// ContractPolicy is the server-owned extension compatibility policy.
type ContractPolicy struct {
	pluginContracts []string
	uiHostAPIs      []string
	required        bool
}

func DefaultContractPolicy() ContractPolicy {
	return ContractPolicy{pluginContracts: []string{extensionv1.BackendContractV1}, uiHostAPIs: []string{extensionv1.UIHostAPIV1}}
}

func NewContractPolicy(pluginContracts, uiHostAPIs []string, required bool) (ContractPolicy, error) {
	plugins, err := extensionv1.NormalizeSupportSet(pluginContracts)
	if err != nil {
		return ContractPolicy{}, err
	}
	uis, err := extensionv1.NormalizeSupportSet(uiHostAPIs)
	if err != nil {
		return ContractPolicy{}, err
	}
	return ContractPolicy{pluginContracts: plugins, uiHostAPIs: uis, required: required}, nil
}

func (p ContractPolicy) withDefaults() ContractPolicy {
	if p.pluginContracts == nil {
		p.pluginContracts = []string{extensionv1.BackendContractV1}
	}
	if p.uiHostAPIs == nil {
		p.uiHostAPIs = []string{extensionv1.UIHostAPIV1}
	}
	return p
}

func (p ContractPolicy) PluginContracts() []string {
	return append([]string(nil), p.withDefaults().pluginContracts...)
}

func (p ContractPolicy) UIHostAPIs() []string {
	return append([]string(nil), p.withDefaults().uiHostAPIs...)
}

func (p ContractPolicy) Required() bool { return p.required }

func (p ContractPolicy) ValidateBackendManifest(raw json.RawMessage) (*extensionv1.Contracts, error) {
	p = p.withDefaults()
	contracts, err := extensionv1.DecodeSpec(raw)
	if err != nil {
		return nil, err
	}
	if err := extensionv1.ValidateDeclaration(contracts, true, false, p.required); err != nil {
		return nil, err
	}
	if contracts == nil {
		return nil, nil
	}
	if contracts.Backend == nil {
		return nil, extensionv1.NewContractError(extensionv1.CodeContractRequired, "spec.contracts.backend", "declaration is required for backend registration")
	}
	if !extensionv1.Intersects(contracts.Backend, p.pluginContracts) {
		return nil, extensionv1.NewContractError(
			extensionv1.CodeContractUnsupported,
			"spec.contracts.backend",
			"no supported contract intersection (declared [%s]; server supports [%s])",
			strings.Join(contracts.Backend, ", "), strings.Join(p.pluginContracts, ", "),
		)
	}
	return contracts, nil
}

func (p ContractPolicy) ValidateUIContracts(contracts *extensionv1.Contracts) (*extensionv1.Contracts, error) {
	p = p.withDefaults()
	if err := extensionv1.ValidateDeclaration(contracts, false, true, p.required); err != nil {
		return nil, err
	}
	if contracts == nil {
		return nil, nil
	}
	if contracts.UI == nil {
		return nil, extensionv1.NewContractError(extensionv1.CodeContractRequired, "spec.contracts.ui", "declaration is required for UI registration")
	}
	supported := false
	for _, id := range p.uiHostAPIs {
		if contracts.UI.HostAPI == id {
			supported = true
			break
		}
	}
	if !supported {
		return nil, extensionv1.NewContractError(
			extensionv1.CodeContractUnsupported,
			"spec.contracts.ui.hostApi",
			"unsupported UI host API %q (server supports [%s])",
			contracts.UI.HostAPI, strings.Join(p.uiHostAPIs, ", "),
		)
	}
	return contracts, nil
}
