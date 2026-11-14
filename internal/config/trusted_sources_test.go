package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testTrustedSourcesYAML = `environment: development
catalog:
  syncInterval: 5m
  sources:
    - id: core
      indexRef: ghcr.io/7k-inari/catalog/index:latest
      trustTier: official
      artifactPrefixes:
        - ghcr.io/7k-inari/catalog/
      publisher:
        issuer: https://token.actions.githubusercontent.com
        repository: 7k-hiroba/workflows
        workflows:
          index: .github/workflows/release.yml
          catalogPackage: .github/workflows/release-oci.yml
          template: .github/workflows/release-oci.yml
          helmChart: .github/workflows/release-chart.yml
          smokeSuite: .github/workflows/release-smoke-suite.yml
        workflowSha: 0123456789abcdef0123456789abcdef01234567
        sourceRepository: 7K-Inari/inari-catalog
        sourceWorkflow: .github/workflows/release.yml
        sourceRef: refs/heads/main
        event: push
        releaseEnvironment: release
template:
  syncInterval: 10m
  sources: []
`

func TestLoadTrustedSourcesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sources.yaml")
	if err := os.WriteFile(path, []byte(testTrustedSourcesYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INARI_TRUSTED_SOURCES_FILE", path)
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.TrustedSources == nil || len(c.TrustedSources.Catalog.Sources) != 1 {
		t.Fatalf("TrustedSources = %+v", c.TrustedSources)
	}
	if c.CatalogSyncInterval != 5*time.Minute || c.TemplateSyncInterval != 10*time.Minute {
		t.Fatalf("intervals = %s / %s", c.CatalogSyncInterval, c.TemplateSyncInterval)
	}
}

func TestLoadTrustedSourcesRejectsInvalidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sources.yaml")
	if err := os.WriteFile(path, []byte("catalog: {sources: [{id: invalid}]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INARI_TRUSTED_SOURCES_FILE", path)
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "INARI_TRUSTED_SOURCES_FILE") {
		t.Fatalf("error = %v, want source file path", err)
	}
}

func TestLoadTrustedSourcesRejectsUnsignedOutsideDevelopment(t *testing.T) {
	for _, environment := range []string{"production", "staging", ""} {
		t.Run("environment="+environment, func(t *testing.T) {
			yaml := strings.Replace(testTrustedSourcesYAML, "environment: development", "environment: "+environment, 1)
			if environment == "" {
				yaml = strings.Replace(yaml, "environment: \n", "", 1)
			}
			yaml = strings.Replace(yaml, "trustTier: official", "trustTier: experimental\n      allowUnsigned: development-only", 1)
			path := filepath.Join(t.TempDir(), "sources.yaml")
			if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("INARI_TRUSTED_SOURCES_FILE", path)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "requires environment development") {
				t.Fatalf("error = %v, want development-only rejection", err)
			}
		})
	}
}

func TestRemovedSourceEnvironmentVariablesFail(t *testing.T) {
	for _, key := range []string{
		"INARI_CATALOG_OCI_INDEX_REF",
		"INARI_CATALOG_OCI_PATH",
		"INARI_SCAFFOLD_TEMPLATE_OCI_INDEX_REF",
		"INARI_SCAFFOLD_TEMPLATE_DIR",
		"INARI_SCAFFOLD_TEMPLATE_VERIFY",
		"INARI_SCAFFOLD_TEMPLATE_COSIGN_IDENTITY",
		"INARI_SCAFFOLD_TEMPLATE_COSIGN_ISSUER",
	} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "legacy")
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "INARI_TRUSTED_SOURCES_FILE") {
				t.Fatalf("error = %v, want replacement", err)
			}
		})
	}
}
