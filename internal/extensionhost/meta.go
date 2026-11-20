package extensionhost

import (
	"context"
	"net/http"

	extensionv1 "github.com/7K-Inari/inari-api/contract/extension/v1"
	"github.com/danielgtaylor/huma/v2"
)

// MetaHandler exposes non-secret server compatibility metadata.
type MetaHandler struct {
	policy        ContractPolicy
	serverVersion string
}

func NewMetaHandler(policy ContractPolicy, serverVersion string) *MetaHandler {
	if serverVersion == "" {
		serverVersion = "dev"
	}
	return &MetaHandler{policy: policy, serverVersion: serverVersion}
}

type contractsOutput struct {
	CacheControl string `header:"Cache-Control"`
	Body         extensionv1.ContractMetadata
}

func (h *MetaHandler) RegisterRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "getMetaContracts", Method: http.MethodGet,
		Path: "/api/v1/meta/contracts", Summary: "Get supported extension contracts",
		Security: []map[string][]string{},
	}, h.contracts)
}

func (h *MetaHandler) contracts(context.Context, *struct{}) (*contractsOutput, error) {
	return &contractsOutput{
		CacheControl: "no-store",
		Body: extensionv1.ContractMetadata{
			PluginContracts: h.policy.PluginContracts(),
			UIHostAPIs:      h.policy.UIHostAPIs(),
			ServerVersion:   h.serverVersion,
		},
	}, nil
}
