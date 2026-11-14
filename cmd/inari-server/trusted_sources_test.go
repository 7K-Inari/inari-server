package main

import (
	"testing"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/config"
)

func TestBuildTrustedSourcesTemplateOnly(t *testing.T) {
	cfg := &config.Config{TrustedSources: &trustedsource.File{
		Template: &trustedsource.SourceGroup{Sources: []trustedsource.Source{{
			ID: "templates", IndexRef: "registry.local/templates/index:latest",
			TrustTier: trustedsource.TrustExperimental, AllowUnsigned: trustedsource.AllowUnsignedDevelopmentOnly,
			ArtifactPrefixes: []string{"registry.local/templates/"},
		}}},
	}}
	catalogSyncs, verifier := buildTrustedSourceSyncs(cfg)
	if len(catalogSyncs) != 0 || verifier == nil {
		t.Fatalf("catalog syncs = %d, verifier = %v; template-only config must still construct admission", len(catalogSyncs), verifier)
	}
	templateSyncs, templates := buildTrustedTemplateSyncs(cfg, verifier)
	if len(templateSyncs) != 1 || templates == nil || len(templates.Sources) != 1 {
		t.Fatalf("template syncs = %+v, sources = %+v", templateSyncs, templates)
	}
}

func TestBuildTrustedSourcesUnconfigured(t *testing.T) {
	sources, verifier := buildTrustedSourceSyncs(&config.Config{})
	if sources != nil || verifier != nil {
		t.Fatalf("unconfigured sources = %+v, verifier = %v", sources, verifier)
	}
}
