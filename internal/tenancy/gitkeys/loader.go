// Package gitkeys loads tenant BYO GitHub App private keys from ESO-rendered
// Secret mounts (ADR-0004, plan §12.2: key material stays cluster-side; only
// references are stored in the DB).
package gitkeys

import (
	"context"
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/7K-Inari/inari-server/internal/types"
)

// Loader reads keys from <MountRoot>/<namespace>/<secretName>/<key>.
type Loader struct{ MountRoot string }

var segment = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)

// ValidateRef checks a secret reference is well-formed (422 at the API).
func ValidateRef(ref *types.GitHubAppSecretRef) error {
	if ref == nil {
		return fmt.Errorf("gitkeys: keyRef is required")
	}
	if !segment.MatchString(ref.Namespace) {
		return fmt.Errorf("gitkeys: invalid namespace %q", ref.Namespace)
	}
	if !segment.MatchString(ref.SecretName) {
		return fmt.Errorf("gitkeys: invalid secretName %q", ref.SecretName)
	}
	if ref.Key == "" || strings.ContainsAny(ref.Key, `/\`) || ref.Key == "." || ref.Key == ".." {
		return fmt.Errorf("gitkeys: invalid key %q", ref.Key)
	}
	return nil
}

// path resolves the mount path, rejecting traversal outside MountRoot.
func (l Loader) path(ref *types.GitHubAppSecretRef) (string, error) {
	if err := ValidateRef(ref); err != nil {
		return "", err
	}
	root, err := filepath.Abs(l.MountRoot)
	if err != nil {
		return "", err
	}
	p := filepath.Join(root, ref.Namespace, ref.SecretName, ref.Key)
	if p != root && !strings.HasPrefix(p, root+string(os.PathSeparator)) {
		return "", fmt.Errorf("gitkeys: reference escapes mount root")
	}
	return p, nil
}

// Load reads and parses the PEM private key for a reference. Errors never
// include key material.
func (l Loader) Load(_ context.Context, ref *types.GitHubAppSecretRef) (*rsa.PrivateKey, error) {
	p, err := l.path(ref)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("gitkeys: read %s/%s/%s: %w", ref.Namespace, ref.SecretName, ref.Key, err)
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(raw)
	if err != nil {
		return nil, fmt.Errorf("gitkeys: parse %s/%s/%s: invalid PEM private key", ref.Namespace, ref.SecretName, ref.Key)
	}
	return key, nil
}
