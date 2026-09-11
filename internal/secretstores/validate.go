package secretstores

import (
	"fmt"
	"regexp"

	"github.com/7K-Inari/inari-server/internal/types"
)

var nameRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// ValidateName enforces a DNS-label store name (used as the ESO SecretStore
// name in-cluster and as the registry lookup key).
func ValidateName(name string) error {
	if len(name) == 0 || len(name) > 63 || !nameRe.MatchString(name) {
		return fmt.Errorf("%w: name must be a lowercase RFC 1123 label (max 63 chars)", ErrInvalidInput)
	}
	return nil
}

// ValidateScope enforces the scope enum.
func ValidateScope(scope string) error {
	switch scope {
	case types.SecretStoreScopePlatform, types.SecretStoreScopeCluster:
		return nil
	}
	return fmt.Errorf("%w: scope must be %q or %q", ErrInvalidInput,
		types.SecretStoreScopePlatform, types.SecretStoreScopeCluster)
}

// ValidateTargets enforces exactly one targeting mode.
func ValidateTargets(t types.SecretStoreTargets) error {
	switch {
	case t.ClusterSetRef != "" && len(t.ClusterIDs) > 0:
		return fmt.Errorf("%w: targets must set either clusterSetRef or clusterIds, not both", ErrInvalidInput)
	case t.ClusterSetRef == "" && len(t.ClusterIDs) == 0:
		return fmt.Errorf("%w: targets must set clusterSetRef or clusterIds", ErrInvalidInput)
	}
	return nil
}

// ValidateProvider enforces exactly one backend, its backend-specific
// required fields, and a complete cluster-side auth secret reference.
// Credential values are not representable here by construction: the schema
// carries references only (plan §4.1).
func ValidateProvider(p types.SecretStoreProvider) error {
	set := 0
	var ref *types.SecretRef
	var kind, missing string
	if p.AWSSM != nil {
		set++
		kind = "awsSM"
		ref = &p.AWSSM.AuthSecretRef
		if p.AWSSM.Region == "" {
			missing = "region"
		}
	}
	if p.Vault != nil {
		set++
		kind = "vault"
		ref = &p.Vault.AuthSecretRef
		if p.Vault.Server == "" {
			missing = "server"
		}
	}
	if p.GCPSM != nil {
		set++
		kind = "gcpsm"
		ref = &p.GCPSM.AuthSecretRef
		if p.GCPSM.ProjectID == "" {
			missing = "projectId"
		}
	}
	if p.AzureKV != nil {
		set++
		kind = "azurekv"
		ref = &p.AzureKV.AuthSecretRef
		if p.AzureKV.VaultURL == "" {
			missing = "vaultUrl"
		}
	}
	if set == 0 {
		return fmt.Errorf("%w: provider must set exactly one of awsSM, vault, gcpsm, azurekv", ErrInvalidInput)
	}
	if set > 1 {
		return fmt.Errorf("%w: provider must set exactly one backend, got %d", ErrInvalidInput, set)
	}
	if missing != "" {
		return fmt.Errorf("%w: provider %s requires %s", ErrInvalidInput, kind, missing)
	}
	if ref.Name == "" || ref.Namespace == "" {
		return fmt.Errorf("%w: provider %s authSecretRef name and namespace are required", ErrInvalidInput, kind)
	}
	return nil
}
