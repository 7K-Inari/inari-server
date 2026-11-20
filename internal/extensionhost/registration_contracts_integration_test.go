//go:build integration

package extensionhost_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	extensionv1 "github.com/7K-Inari/inari-api/contract/extension/v1"
	"github.com/7K-Inari/inari-server/internal/extensionhost"
)

func TestBackendContractRegistrationPersistsAndRejectsUnsupported(t *testing.T) {
	svc := itService(t)
	ctx := context.Background()
	manifest := json.RawMessage(`{"contracts":{"backend":["inari.plugin.v1","inari.plugin.v2"]}}`)
	e, _, err := svc.Register(ctx, "user-1", extensionhost.RegisterInput{OrgID: "org:1", Name: "valid", Version: "1.0.0", Manifest: manifest})
	if err != nil || e.Contracts == nil || len(e.Contracts.Backend) != 2 {
		t.Fatalf("register contracts = %#v, %v", e.Contracts, err)
	}
	got, err := svc.Get(ctx, "org:1", e.ID)
	if err != nil || got.Contracts == nil || len(got.Contracts.Backend) != 2 {
		t.Fatalf("persisted contracts = %#v, %v", got.Contracts, err)
	}

	_, _, err = svc.Register(ctx, "user-1", extensionhost.RegisterInput{
		OrgID: "org:1", Name: "unsupported", Version: "1.0.0",
		Manifest: json.RawMessage(`{"contracts":{"backend":["inari.plugin.v2"]}}`),
	})
	var contractErr *extensionv1.ContractError
	if !errors.As(err, &contractErr) || contractErr.Code != extensionv1.CodeContractUnsupported {
		t.Fatalf("unsupported error = %#v", err)
	}
	list, _ := svc.List(ctx, "org:1")
	if len(list) != 1 {
		t.Fatalf("rejected registration mutated registry: %+v", list)
	}

	policy, err := extensionhost.NewContractPolicy([]string{extensionv1.BackendContractV1}, []string{extensionv1.UIHostAPIV1}, true)
	if err != nil {
		t.Fatal(err)
	}
	svc.WithContractPolicy(policy)
	_, _, err = svc.Register(ctx, "user-1", extensionhost.RegisterInput{OrgID: "org:1", Name: "legacy", Version: "1.0.0"})
	if !errors.As(err, &contractErr) || contractErr.Code != extensionv1.CodeContractRequired {
		t.Fatalf("required legacy error = %#v", err)
	}
}

func TestUIContractsPersistAndPreserveBackendHalf(t *testing.T) {
	svc := itService(t)
	ctx := context.Background()
	backend, _, err := svc.Register(ctx, "user-1", extensionhost.RegisterInput{
		OrgID: "org:1", Name: "paired", Version: "1.0.0",
		Manifest: json.RawMessage(`{"contracts":{"backend":["inari.plugin.v1"]}}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	uiContracts := &extensionv1.Contracts{UI: &extensionv1.UIContract{SDK: ">=0.1.8 <2.0.0", HostAPI: extensionv1.UIHostAPIV1}}
	e, err := svc.RegisterUi(ctx, "user-1", extensionhost.RegisterUiInput{
		OrgID: "org:1", Name: "paired", Version: "1.0.0", RemoteEntry: "https://example.com/remote.js", Contracts: uiContracts,
	})
	if err != nil || e.Contracts == nil || e.Contracts.UI == nil || len(e.Contracts.Backend) != 1 {
		t.Fatalf("paired contracts = %#v, %v", e.Contracts, err)
	}
	got, err := svc.GetUi(ctx, "org:1", "paired")
	if err != nil || got.Contracts == nil || got.Contracts.UI.HostAPI != extensionv1.UIHostAPIV1 {
		t.Fatalf("persisted UI contracts = %#v, %v", got.Contracts, err)
	}
	if got.ID != backend.ID {
		t.Fatal("paired registration changed backend row")
	}

	_, err = svc.RegisterUi(ctx, "user-1", extensionhost.RegisterUiInput{
		OrgID: "org:1", Name: "paired", Version: "1.0.1", RemoteEntry: "https://example.com/remote.js",
	})
	if err != nil {
		t.Fatalf("optional UI update erased/failed declaration: %v", err)
	}
	_, err = svc.RegisterUi(ctx, "user-1", extensionhost.RegisterUiInput{
		OrgID: "org:1", Name: "unsupported-ui", Version: "1.0.0", RemoteEntry: "https://example.com/remote.js",
		Contracts: &extensionv1.Contracts{UI: &extensionv1.UIContract{SDK: "^0.1.8", HostAPI: "inari.ui.v2"}},
	})
	var contractErr *extensionv1.ContractError
	if !errors.As(err, &contractErr) || contractErr.Code != extensionv1.CodeContractUnsupported {
		t.Fatalf("unsupported UI error = %#v", err)
	}
}
