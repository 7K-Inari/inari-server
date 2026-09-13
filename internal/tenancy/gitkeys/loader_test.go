package gitkeys

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func writeKey(t *testing.T, root, ns, secret, key string) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	dir := filepath.Join(root, ns, secret)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, key)
	if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoaderLoadsMountedKey(t *testing.T) {
	root := t.TempDir()
	writeKey(t, root, "tenant-acme", "gh-app", "private-key.pem")
	l := Loader{MountRoot: root}
	k, err := l.Load(context.Background(), &types.GitHubAppSecretRef{
		Namespace: "tenant-acme", SecretName: "gh-app", Key: "private-key.pem",
	})
	if err != nil {
		t.Fatal(err)
	}
	if k == nil || k.N == nil {
		t.Fatal("expected parsed RSA key")
	}
}

func TestLoaderRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	l := Loader{MountRoot: root}
	for _, ref := range []*types.GitHubAppSecretRef{
		{Namespace: "..", SecretName: "x", Key: "k"},
		{Namespace: "ns", SecretName: "../x", Key: "k"},
		{Namespace: "ns", SecretName: "x", Key: "../../etc/passwd"},
		{Namespace: "ns/sub", SecretName: "x", Key: "k"},
	} {
		if _, err := l.Load(context.Background(), ref); err == nil {
			t.Errorf("ref %+v: want traversal rejection", ref)
		}
	}
}

func TestLoaderMissingFileRedacted(t *testing.T) {
	l := Loader{MountRoot: t.TempDir()}
	_, err := l.Load(context.Background(), &types.GitHubAppSecretRef{Namespace: "ns", SecretName: "x", Key: "k"})
	if err == nil {
		t.Fatal("want error for missing key file")
	}
}

func TestLoaderBadPEM(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "ns", "x")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "k"), []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := Loader{MountRoot: root}
	if _, err := l.Load(context.Background(), &types.GitHubAppSecretRef{Namespace: "ns", SecretName: "x", Key: "k"}); err == nil {
		t.Fatal("want parse error")
	}
}

func TestValidateRef(t *testing.T) {
	good := &types.GitHubAppSecretRef{Namespace: "tenant-acme", SecretName: "gh-app", Key: "private-key.pem"}
	if err := ValidateRef(good); err != nil {
		t.Fatalf("valid ref rejected: %v", err)
	}
	for _, bad := range []*types.GitHubAppSecretRef{
		nil,
		{Namespace: "", SecretName: "x", Key: "k"},
		{Namespace: "ns", SecretName: "", Key: "k"},
		{Namespace: "ns", SecretName: "x", Key: ""},
		{Namespace: "NS_BAD", SecretName: "x", Key: "k"},
		{Namespace: "ns", SecretName: "bad name", Key: "k"},
		{Namespace: "ns", SecretName: "x", Key: "a/b"},
	} {
		if err := ValidateRef(bad); err == nil {
			t.Errorf("ref %+v: want validation error", bad)
		}
	}
}
