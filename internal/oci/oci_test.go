package oci

import (
	"archive/tar"
	"bytes"
	"testing"
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
