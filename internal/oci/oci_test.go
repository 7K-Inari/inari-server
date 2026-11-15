package oci

import (
	"archive/tar"
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func tarBytes(t *testing.T, entries []tar.Header, contents [][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i, header := range entries {
		if err := tw.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if len(contents) > i && len(contents[i]) > 0 {
			if _, err := tw.Write(contents[i]); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestUntarRejectsTraversalLinksAndDuplicatePaths(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header tar.Header
	}{
		{"traversal", tar.Header{Name: "../escape", Typeflag: tar.TypeReg, Size: 1, Mode: 0o600}},
		{"absolute", tar.Header{Name: "/escape", Typeflag: tar.TypeReg, Size: 1, Mode: 0o600}},
		{"symlink", tar.Header{Name: "skeleton/link", Typeflag: tar.TypeSymlink, Linkname: "../escape", Mode: 0o600}},
		{"directory allowed", tar.Header{Name: "skeleton/", Typeflag: tar.TypeDir, Mode: 0o755}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var contents [][]byte
			if tc.header.Typeflag == tar.TypeReg {
				contents = [][]byte{{'x'}}
			}
			raw := tarBytes(t, []tar.Header{tc.header}, contents)
			_, err := untar(raw)
			if tc.name == "directory allowed" {
				if err != nil {
					t.Fatalf("directory rejected: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected unsafe archive entry to fail")
			}
		})
	}

	raw := tarBytes(t,
		[]tar.Header{{Name: "schema.json", Typeflag: tar.TypeReg, Size: 1, Mode: 0o600}, {Name: "./schema.json", Typeflag: tar.TypeReg, Size: 1, Mode: 0o600}},
		[][]byte{{'a'}, {'b'}},
	)
	if _, err := untar(raw); err == nil {
		t.Fatal("expected duplicate normalized path to fail")
	}
}

func TestUntarRejectsOversizedContent(t *testing.T) {
	raw := tarBytes(t,
		[]tar.Header{{Name: "large", Typeflag: tar.TypeReg, Size: 32, Mode: 0o600}},
		[][]byte{bytes.Repeat([]byte{'x'}, 32)},
	)
	limits := Limits{MaxFileBytes: 4, MaxTotalBytes: 8, MaxLayerBytes: 1024, MaxFiles: 2}
	if _, err := untarWithLimits(raw, limits); err == nil {
		t.Fatal("expected file size limit to fail")
	}
}

func TestUntarRejectsTooManyFiles(t *testing.T) {
	raw := tarBytes(t,
		[]tar.Header{{Name: "a", Typeflag: tar.TypeReg, Size: 1, Mode: 0o600}, {Name: "b", Typeflag: tar.TypeReg, Size: 1, Mode: 0o600}},
		[][]byte{{'a'}, {'b'}},
	)
	limits := Limits{MaxFileBytes: 4, MaxTotalBytes: 8, MaxLayerBytes: 1024, MaxFiles: 1}
	if _, err := untarWithLimits(raw, limits); err == nil {
		t.Fatal("expected file count limit to fail")
	}
}

type boundedTestLayer struct {
	title     string
	mediaType string
	raw       []byte
}

func pushBoundedTestArtifact(t *testing.T, layers []boundedTestLayer) string {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	img := empty.Image
	var err error
	for _, layer := range layers {
		img, err = mutate.Append(img, mutate.Addendum{
			Layer:       static.NewLayer(layer.raw, types.MediaType(layer.mediaType)),
			Annotations: map[string]string{"org.opencontainers.image.title": layer.title},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	host := strings.TrimPrefix(srv.URL, "http://")
	ref, err := name.ParseReference(host+"/bounded/artifact:latest", name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatal(err)
	}
	return ref.String()
}

func boundedTar(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	return tarBytes(t, []tar.Header{{Name: name, Typeflag: tar.TypeReg, Size: int64(len(content)), Mode: 0o600}}, [][]byte{content})
}

func TestFetchEnforcesLimitsAcrossLayers(t *testing.T) {
	const tarMediaType = "application/vnd.inari.test.tar"
	t.Run("global file count", func(t *testing.T) {
		ref := pushBoundedTestArtifact(t, []boundedTestLayer{
			{title: "first.tar", mediaType: tarMediaType, raw: tarBytes(t,
				[]tar.Header{{Name: "a", Typeflag: tar.TypeReg, Size: 1, Mode: 0o600}, {Name: "b", Typeflag: tar.TypeReg, Size: 1, Mode: 0o600}},
				[][]byte{{'a'}, {'b'}},
			)},
			{title: "second.tar", mediaType: tarMediaType, raw: boundedTar(t, "c", []byte{'c'})},
		})
		fetcher := Fetcher{Insecure: true, Limits: Limits{MaxFiles: 2, MaxFileBytes: 4, MaxTotalBytes: 8, MaxLayerBytes: 8192}}
		if _, err := fetcher.Fetch(t.Context(), ref); err == nil || !strings.Contains(err.Error(), "global file/content limits") {
			t.Fatalf("error = %v, want aggregate file-count rejection", err)
		}
	})
	t.Run("global uncompressed bytes", func(t *testing.T) {
		ref := pushBoundedTestArtifact(t, []boundedTestLayer{
			{title: "first.tar", mediaType: tarMediaType, raw: boundedTar(t, "a", bytes.Repeat([]byte{'a'}, 6))},
			{title: "second.tar", mediaType: tarMediaType, raw: boundedTar(t, "b", bytes.Repeat([]byte{'b'}, 6))},
		})
		fetcher := Fetcher{Insecure: true, Limits: Limits{MaxFiles: 10, MaxFileBytes: 6, MaxTotalBytes: 8, MaxLayerBytes: 8192}}
		if _, err := fetcher.Fetch(t.Context(), ref); err == nil || !strings.Contains(err.Error(), "archive exceeds") {
			t.Fatalf("error = %v, want aggregate uncompressed-size rejection", err)
		}
	})
	t.Run("plain file bytes", func(t *testing.T) {
		ref := pushBoundedTestArtifact(t, []boundedTestLayer{
			{title: "large.txt", mediaType: "application/octet-stream", raw: bytes.Repeat([]byte{'x'}, 5)},
		})
		fetcher := Fetcher{Insecure: true, Limits: Limits{MaxFiles: 10, MaxFileBytes: 4, MaxTotalBytes: 8, MaxLayerBytes: 8192}}
		if _, err := fetcher.Fetch(t.Context(), ref); err == nil || !strings.Contains(err.Error(), `file "large.txt" exceeds 4 bytes`) {
			t.Fatalf("error = %v, want plain-file size rejection", err)
		}
	})
}
