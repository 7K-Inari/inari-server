// Package oci fetches oras-style directory-push OCI artifacts: every
// layer carries its file name in the org.opencontainers.image.title
// annotation. Shared by the catalog package sync (internal/catalog) and
// the software-template puller (internal/scaffold) — M8.W6 extraction, no
// behavior change.
package oci

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

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

// Artifact is one pulled oras directory-push artifact: the resolved
// content digest, the manifest artifact type (empty for legacy pushes
// that don't set it), and every layer keyed by its title-annotation file
// name.
type Artifact struct {
	MediaType string
	Digest    string // "sha256:..."
	Files     map[string][]byte
}

// FetchDir pulls an oras directory-push artifact and returns every layer
// keyed by its title-annotation file name.
func (f *Fetcher) FetchDir(ctx context.Context, ref string) (map[string][]byte, error) {
	a, err := f.Fetch(ctx, ref)
	if err != nil {
		return nil, err
	}
	return a.Files, nil
}

// Fetch pulls an oras directory-push artifact with its metadata.
func (f *Fetcher) Fetch(ctx context.Context, ref string) (*Artifact, error) {
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
		// oras directory-pushes store the whole directory as one tar(+gzip)
		// layer flagged io.deis.oras.content.unpack; expand it into
		// per-file entries (paths like "packages/<pkg>/package.yaml").
		if ld.Annotations["io.deis.oras.content.unpack"] == "true" ||
			strings.Contains(string(ld.MediaType), "tar") {
			tarFiles, err := untar(raw)
			if err != nil {
				return nil, fmt.Errorf("oci: %s: unpack layer %s: %w", ref, title, err)
			}
			for name, content := range tarFiles {
				files[name] = content
			}
			continue
		}
		if title == "" {
			continue
		}
		files[title] = raw
	}
	return &Artifact{MediaType: string(manifest.ArtifactType), Digest: desc.Digest.String(), Files: files}, nil
}

// untar extracts a (possibly gzipped) tar blob into a name→content map.
// Leading "./" is stripped from entry names.
func untar(raw []byte) (map[string][]byte, error) {
	var r io.Reader = bytes.NewReader(raw)
	if len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		defer func() { _ = gz.Close() }()
		r = gz
	}
	out := map[string][]byte{}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		out[strings.TrimPrefix(hdr.Name, "./")] = content
	}
}
