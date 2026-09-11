// Package oci fetches oras-style directory-push OCI artifacts: every
// layer carries its file name in the org.opencontainers.image.title
// annotation. Shared by the catalog package sync (internal/catalog) and
// the software-template puller (internal/scaffold) — M8.W6 extraction, no
// behavior change.
package oci

import (
	"context"
	"fmt"
	"io"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Fetcher pulls artifact layer contents from an OCI registry.
type Fetcher struct {
	// Keychain overrides registry auth (default: authn.DefaultKeychain).
	Keychain authn.Keychain
	// Insecure allows plain-HTTP registries (tests/dev).
	Insecure bool
}

func (f *Fetcher) remoteOpts(ctx context.Context) []remote.Option {
	kc := f.Keychain
	if kc == nil {
		kc = authn.DefaultKeychain
	}
	return []remote.Option{remote.WithAuthFromKeychain(kc), remote.WithContext(ctx)}
}

// FetchDir pulls an oras directory-push artifact and returns every layer
// keyed by its title-annotation file name.
func (f *Fetcher) FetchDir(ctx context.Context, ref string) (map[string][]byte, error) {
	opts := []name.Option{}
	if f.Insecure {
		opts = append(opts, name.Insecure)
	}
	r, err := name.ParseReference(ref, opts...)
	if err != nil {
		return nil, fmt.Errorf("oci: parse ref %q: %w", ref, err)
	}
	desc, err := remote.Get(r, f.remoteOpts(ctx)...)
	if err != nil {
		return nil, err
	}
	img, err := desc.Image()
	if err != nil {
		return nil, err
	}
	manifest, err := img.Manifest()
	if err != nil {
		return nil, err
	}
	layers, err := img.Layers()
	if err != nil {
		return nil, err
	}
	byDigest := map[v1.Hash]v1.Layer{}
	for _, l := range layers {
		d, err := l.Digest()
		if err != nil {
			return nil, err
		}
		byDigest[d] = l
	}
	files := map[string][]byte{}
	for _, ld := range manifest.Layers {
		title := ld.Annotations["org.opencontainers.image.title"]
		if title == "" {
			continue
		}
		l, ok := byDigest[ld.Digest]
		if !ok {
			return nil, fmt.Errorf("oci: %s: layer %s not found", ref, ld.Digest)
		}
		rc, err := l.Uncompressed()
		if err != nil {
			return nil, err
		}
		raw, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			return nil, err
		}
		files[title] = raw
	}
	return files, nil
}
