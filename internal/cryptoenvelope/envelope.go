// Package cryptoenvelope implements the KEK/DEK envelope encryption used by
// the W3 credential vault (plan §5.8): each row's secret is encrypted under a
// fresh random DEK (AES-256-GCM), and the DEK is wrapped under the platform
// KEK. Only ciphertext ever reaches the database; the KEK comes from a
// mounted file or (dev only) an env var, following the gitkeys discipline —
// key material never appears in errors or logs.
package cryptoenvelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// KeySize is the required KEK/DEK size in bytes (AES-256).
const KeySize = 32

// ErrDecrypt is returned for any decryption failure (wrong KEK, corrupted
// ciphertext, AAD mismatch); the cause is never distinguished to callers.
var ErrDecrypt = errors.New("cryptoenvelope: decryption failed")

// Cipher encrypts row secrets under per-row DEKs wrapped by the KEK.
type Cipher struct {
	kek []byte
}

// New builds a Cipher from a 32-byte KEK (copied).
func New(kek []byte) (*Cipher, error) {
	if len(kek) != KeySize {
		return nil, fmt.Errorf("cryptoenvelope: KEK must be %d bytes, got %d", KeySize, len(kek))
	}
	k := make([]byte, KeySize)
	copy(k, kek)
	return &Cipher{kek: k}, nil
}

// LoadKEK reads the platform KEK from INARI_CREDENTIAL_KEK_FILE (mounted
// file, preferred) or INARI_CREDENTIAL_KEK (base64, dev only). The value is
// base64-encoded 32 bytes in both cases. Errors never include key material.
func LoadKEK() ([]byte, error) {
	var raw string
	if path := os.Getenv("INARI_CREDENTIAL_KEK_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("cryptoenvelope: read KEK file: %v", err)
		}
		raw = strings.TrimSpace(string(b))
	} else {
		raw = strings.TrimSpace(os.Getenv("INARI_CREDENTIAL_KEK"))
	}
	if raw == "" {
		return nil, errors.New("cryptoenvelope: INARI_CREDENTIAL_KEK_FILE or INARI_CREDENTIAL_KEK required")
	}
	kek, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(kek) != KeySize {
		return nil, fmt.Errorf("cryptoenvelope: KEK must be base64-encoded %d bytes", KeySize)
	}
	return kek, nil
}

// Encrypt returns (data ciphertext, wrapped DEK). Both include their GCM
// nonce as a prefix. aad binds the ciphertext to its row identity (e.g.
// "agent_command_credentials:cred:<uuid>") so rows cannot be transplanted.
func (c *Cipher) Encrypt(plaintext, aad []byte) (dataEnc, dekEnc []byte, err error) {
	dek := make([]byte, KeySize)
	if _, err := rand.Read(dek); err != nil {
		return nil, nil, fmt.Errorf("cryptoenvelope: generate DEK: %w", err)
	}
	defer Zero(dek)
	dataEnc, err = seal(dek, plaintext, aad)
	if err != nil {
		return nil, nil, err
	}
	dekEnc, err = seal(c.kek, dek, aad)
	if err != nil {
		Zero(dataEnc)
		return nil, nil, err
	}
	return dataEnc, dekEnc, nil
}

// Decrypt unwraps the DEK and decrypts the row secret. Any failure is
// reported as ErrDecrypt.
func (c *Cipher) Decrypt(dataEnc, dekEnc, aad []byte) ([]byte, error) {
	dek, err := open(c.kek, dekEnc, aad)
	if err != nil {
		return nil, err
	}
	defer Zero(dek)
	return open(dek, dataEnc, aad)
}

// Zero wipes a plaintext buffer in place.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func seal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cryptoenvelope: nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func open(key, blob, aad []byte) ([]byte, error) {
	gcm, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, ErrDecrypt
	}
	plain, err := gcm.Open(nil, blob[:gcm.NonceSize()], blob[gcm.NonceSize():], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cryptoenvelope: %w", err)
	}
	return cipher.NewGCM(block)
}
