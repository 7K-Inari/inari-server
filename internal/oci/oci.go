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
	"path"
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
	// Limits bounds layer/file counts and uncompressed bytes. Zero uses defaults.
	Limits Limits
}

func (l Limits) withDefaults() Limits {
	if l.MaxFiles <= 0 {
		l.MaxFiles = 2048
	}
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = 8 << 20
	}
	if l.MaxTotalBytes <= 0 {
		l.MaxTotalBytes = 64 << 20
	}
	if l.MaxLayerBytes <= 0 {
		l.MaxLayerBytes = 32 << 20
	}
	return l
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
	MediaType       string
	ConfigMediaType string
	LayerMediaTypes []string
	Digest          string // "sha256:..."
	Files           map[string][]byte
}

// Limits bounds registry and decompression work. Zero fields use safe defaults.
type Limits struct {
	MaxFiles      int
	MaxFileBytes  int64
	MaxTotalBytes int64
	MaxLayerBytes int64
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
	limits := f.Limits.withDefaults()
	byDigest := map[v1.Hash]v1.Layer{}
	for _, l := range layers {
		d, err := l.Digest()
		if err != nil {
			return nil, err
		}
		byDigest[d] = l
	}
	files := map[string][]byte{}
	layerMediaTypes := make([]string, 0, len(manifest.Layers))
	var totalBytes int64
	for _, ld := range manifest.Layers {
		layerMediaTypes = append(layerMediaTypes, string(ld.MediaType))
		if ld.Size > limits.MaxLayerBytes {
			return nil, fmt.Errorf("oci: %s: layer exceeds %d bytes", ref, limits.MaxLayerBytes)
		}
		title := ld.Annotations["org.opencontainers.image.title"]
		l, ok := byDigest[ld.Digest]
		if !ok {
			return nil, fmt.Errorf("oci: %s: layer %s not found", ref, ld.Digest)
		}
		rc, err := l.Uncompressed()
		if err != nil {
			return nil, err
		}
		raw, err := readBounded(rc, limits.MaxLayerBytes)
		_ = rc.Close()
		if err != nil {
			return nil, err
		}
		totalBytes += int64(len(raw))
		if totalBytes > limits.MaxTotalBytes {
			return nil, fmt.Errorf("oci: %s: uncompressed content exceeds %d bytes", ref, limits.MaxTotalBytes)
		}
		// oras directory-pushes store the whole directory as one tar(+gzip)
		// layer flagged io.deis.oras.content.unpack; expand it into
		// per-file entries (paths like "packages/<pkg>/package.yaml").
		if ld.Annotations["io.deis.oras.content.unpack"] == "true" ||
			strings.Contains(string(ld.MediaType), "tar") {
			tarFiles, err := untarWithLimits(raw, limits)
			if err != nil {
				return nil, fmt.Errorf("oci: %s: unpack layer %s: %w", ref, title, err)
			}
			for name, content := range tarFiles {
				if _, exists := files[name]; exists {
					return nil, fmt.Errorf("oci: %s: duplicate file path %q", ref, name)
				}
				files[name] = content
			}
			continue
		}
		if title == "" {
			continue
		}
		clean, err := cleanArtifactPath(title)
		if err != nil {
			return nil, fmt.Errorf("oci: %s: %w", ref, err)
		}
		if _, exists := files[clean]; exists {
			return nil, fmt.Errorf("oci: %s: duplicate file path %q", ref, clean)
		}
		files[clean] = raw
	}
	return &Artifact{
		MediaType: string(manifest.ArtifactType), ConfigMediaType: string(manifest.Config.MediaType),
		LayerMediaTypes: layerMediaTypes, Digest: desc.Digest.String(), Files: files,
	}, nil
}

func readBounded(r io.Reader, max int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("content exceeds %d bytes", max)
	}
	return raw, nil
}

func cleanArtifactPath(name string) (string, error) {
	if name == "" || strings.Contains(name, "\\") || path.IsAbs(name) {
		return "", fmt.Errorf("unsafe artifact path %q", name)
	}
	clean := path.Clean(strings.TrimPrefix(name, "./"))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("unsafe artifact path %q", name)
	}
	return clean, nil
}

// untar extracts a (possibly gzipped) tar blob into a name→content map using
// safe defaults. Leading "./" is stripped before path validation.
func untar(raw []byte) (map[string][]byte, error) {
	return untarWithLimits(raw, Limits{})
}

func untarWithLimits(raw []byte, limits Limits) (map[string][]byte, error) {
	limits = limits.withDefaults()
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
	var total int64
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("unsupported archive entry type %d for %q", hdr.Typeflag, hdr.Name)
		}
		if len(out) >= limits.MaxFiles {
			return nil, fmt.Errorf("archive contains more than %d files", limits.MaxFiles)
		}
		clean, err := cleanArtifactPath(hdr.Name)
		if err != nil {
			return nil, err
		}
		if _, exists := out[clean]; exists {
			return nil, fmt.Errorf("duplicate artifact path %q", clean)
		}
		if hdr.Size > limits.MaxFileBytes {
			return nil, fmt.Errorf("file %q exceeds %d bytes", clean, limits.MaxFileBytes)
		}
		content, err := readBounded(tr, limits.MaxFileBytes)
		if err != nil {
			return nil, err
		}
		total += int64(len(content))
		if total > limits.MaxTotalBytes {
			return nil, fmt.Errorf("archive exceeds %d uncompressed bytes", limits.MaxTotalBytes)
		}
		out[clean] = content
	}
}
