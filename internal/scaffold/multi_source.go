package scaffold

import (
	"context"
	"fmt"
	"strings"
)

// MultiTemplateSource routes exact artifact refs to their configured source.
// It is the only multi-source TemplateSource used by live wiring.
type MultiTemplateSource struct {
	Sources []*RegistryTemplateSource
}

func (m *MultiTemplateSource) Pull(ctx context.Context) ([]TemplatePackage, error) {
	var out []TemplatePackage
	for _, source := range m.Sources {
		packages, err := source.Pull(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, packages...)
	}
	return out, nil
}

func (m *MultiTemplateSource) Get(ctx context.Context, name, version string) (*TemplatePackage, error) {
	var found *TemplatePackage
	for _, source := range m.Sources {
		pkg, err := source.Get(ctx, name, version)
		if err == nil {
			if found != nil {
				return nil, fmt.Errorf("scaffold: template %s@%s is ambiguous across sources; use its exact artifact ref", name, version)
			}
			found = pkg
		}
	}
	if found == nil {
		return nil, fmt.Errorf("scaffold: template %s version %s not found", name, version)
	}
	return found, nil
}

func (m *MultiTemplateSource) GetArtifact(ctx context.Context, ref, version, expectedSkeletonDigest string) (*TemplatePackage, error) {
	for _, source := range m.Sources {
		for _, prefix := range source.Source.ArtifactPrefixes {
			if strings.HasPrefix(ref, prefix) {
				return source.GetArtifact(ctx, ref, version, expectedSkeletonDigest)
			}
		}
	}
	return nil, fmt.Errorf("scaffold: template artifact %q is outside every configured source namespace", ref)
}
