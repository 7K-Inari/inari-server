// Envelope encryption for user_git_connections rows (W4, plan §5.8): each
// row's refresh token is encrypted under a fresh random per-row DEK
// (AES-256-GCM), and the DEK is wrapped by a KEK behind the KEK interface —
// a static AES-256-GCM key (mounted file / dev env, same discipline as
// cryptoenvelope and gitkeys) or an OpenBao/Vault transit key. Only
// ciphertext ever reaches the database; key and token material never appear
// in errors or logs.
package usergit

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// keySize is the required DEK and static-KEK size in bytes (AES-256).
const keySize = 32

// ErrDecrypt is returned for any decryption failure (wrong KEK, corrupted
// ciphertext, AAD mismatch, transit unwrap failure); the cause is never
// distinguished to callers.
var ErrDecrypt = errors.New("usergit: decryption failed")

// KEK wraps and unwraps per-row DEKs. Implementations must never include
// key material or plaintext in returned errors.
type KEK interface {
	Wrap(dek []byte) ([]byte, error)
	Unwrap(wrapped []byte) ([]byte, error)
}

// Cipher encrypts row secrets under per-row DEKs wrapped by a KEK.
type Cipher struct {
	kek KEK
}

func NewCipher(kek KEK) (*Cipher, error) {
	if kek == nil {
		return nil, errors.New("usergit: KEK required")
	}
	return &Cipher{kek: kek}, nil
}

// Encrypt returns (data ciphertext, wrapped DEK). The data ciphertext
// includes its GCM nonce as a prefix; aad binds the ciphertext to its row
// identity ("user_git_connections:ugc:<uuid>") so rows cannot be
// transplanted.
func (c *Cipher) Encrypt(plaintext []byte, aad string) (dataEnc, dekEnc []byte, err error) {
	dek := make([]byte, keySize)
	if _, err := rand.Read(dek); err != nil {
		return nil, nil, fmt.Errorf("usergit: generate DEK: %w", err)
	}
	defer Zero(dek)
	dataEnc, err = seal(dek, plaintext, []byte(aad))
	if err != nil {
		return nil, nil, err
	}
	dekEnc, err = c.kek.Wrap(dek)
	if err != nil {
		Zero(dataEnc)
		return nil, nil, err
	}
	return dataEnc, dekEnc, nil
}

// Decrypt unwraps the DEK and decrypts the row secret. Any failure is
// reported as ErrDecrypt.
func (c *Cipher) Decrypt(dataEnc, dekEnc []byte, aad string) ([]byte, error) {
	dek, err := c.kek.Unwrap(dekEnc)
	if err != nil {
		return nil, ErrDecrypt
	}
	defer Zero(dek)
	plain, err := open(dek, dataEnc, []byte(aad))
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
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
		return nil, fmt.Errorf("usergit: nonce: %w", err)
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
		return nil, fmt.Errorf("usergit: %w", err)
	}
	return cipher.NewGCM(block)
}

// StaticKEK wraps DEKs under a local 32-byte AES-256-GCM key (dev and
// single-KEK deployments; same discipline as cryptoenvelope).
type StaticKEK struct {
	key []byte
}

// NewStaticKEK builds a StaticKEK from a 32-byte key (copied).
func NewStaticKEK(key []byte) (*StaticKEK, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("usergit: static KEK must be %d bytes, got %d", keySize, len(key))
	}
	k := make([]byte, keySize)
	copy(k, key)
	return &StaticKEK{key: k}, nil
}

func (k *StaticKEK) Wrap(dek []byte) ([]byte, error) {
	return seal(k.key, dek, []byte("user_git_connections:dek"))
}

func (k *StaticKEK) Unwrap(wrapped []byte) ([]byte, error) {
	return open(k.key, wrapped, []byte("user_git_connections:dek"))
}

// LoadStaticKEK reads the static KEK from the first available source:
// INARI_USERGIT_KEK_FILE, then the shared credential-vault sources
// INARI_CREDENTIAL_KEK_FILE / INARI_CREDENTIAL_KEK (dev parity so e2e needs
// a single key file), then INARI_USERGIT_KEK (base64, dev only). The value
// is base64-encoded 32 bytes in every case. Errors never include key
// material.
func LoadStaticKEK() ([]byte, error) {
	if path := os.Getenv("INARI_USERGIT_KEK_FILE"); path != "" {
		return decodeKEKFile(path)
	}
	if path := os.Getenv("INARI_CREDENTIAL_KEK_FILE"); path != "" {
		return decodeKEKFile(path)
	}
	for _, env := range []string{"INARI_USERGIT_KEK", "INARI_CREDENTIAL_KEK"} {
		if raw := strings.TrimSpace(os.Getenv(env)); raw != "" {
			return decodeKEK(raw)
		}
	}
	return nil, errors.New("usergit: INARI_USERGIT_KEK_FILE (or credential KEK fallback) required")
}

func decodeKEKFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("usergit: read KEK file: %v", err)
	}
	return decodeKEK(strings.TrimSpace(string(b)))
}

func decodeKEK(raw string) ([]byte, error) {
	kek, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(kek) != keySize {
		return nil, fmt.Errorf("usergit: KEK must be base64-encoded %d bytes", keySize)
	}
	return kek, nil
}

// TransitKEK wraps DEKs with an OpenBao/Vault transit key. The wrapped DEK
// is the transit ciphertext blob ("vault:v1:...") stored verbatim in the
// dek_enc column. The transit token is never logged and never appears in
// errors.
type TransitKEK struct {
	addr   string
	mount  string
	key    string
	token  string
	client *http.Client
}

// NewTransitKEK builds a transit-backed KEK. addr is the OpenBao base URL
// (https required except loopback), mount the transit engine mount
// ("transit" default), keyName the transit key, token the auth token.
func NewTransitKEK(addr, mount, keyName, token string, client *http.Client) (*TransitKEK, error) {
	if addr == "" || keyName == "" || token == "" {
		return nil, errors.New("usergit: transit KEK requires addr, key name and token")
	}
	if !strings.HasPrefix(addr, "https://") && !strings.Contains(addr, "://localhost") && !strings.Contains(addr, "://127.0.0.1") {
		return nil, errors.New("usergit: transit addr must be https (loopback http allowed for dev)")
	}
	if mount == "" {
		mount = "transit"
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &TransitKEK{addr: strings.TrimRight(addr, "/"), mount: mount, key: keyName, token: token, client: client}, nil
}

type transitEncryptResponse struct {
	Data struct {
		Ciphertext string `json:"ciphertext"`
	} `json:"data"`
}

type transitDecryptResponse struct {
	Data struct {
		Plaintext string `json:"plaintext"`
	} `json:"data"`
}

func (t *TransitKEK) Wrap(dek []byte) ([]byte, error) {
	body, _ := json.Marshal(map[string]string{"plaintext": base64.StdEncoding.EncodeToString(dek)})
	var out transitEncryptResponse
	if err := t.transitCall("encrypt", body, &out); err != nil {
		return nil, err
	}
	if out.Data.Ciphertext == "" {
		return nil, errors.New("usergit: transit encrypt returned empty ciphertext")
	}
	return []byte(out.Data.Ciphertext), nil
}

func (t *TransitKEK) Unwrap(wrapped []byte) ([]byte, error) {
	body, _ := json.Marshal(map[string]string{"ciphertext": string(wrapped)})
	var out transitDecryptResponse
	if err := t.transitCall("decrypt", body, &out); err != nil {
		return nil, ErrDecrypt
	}
	dek, err := base64.StdEncoding.DecodeString(out.Data.Plaintext)
	if err != nil || len(dek) != keySize {
		return nil, ErrDecrypt
	}
	return dek, nil
}

func (t *TransitKEK) transitCall(op string, body []byte, out any) error {
	url := fmt.Sprintf("%s/v1/%s/%s/%s", t.addr, t.mount, op, t.key)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("usergit: transit %s: %w", op, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", t.token)
	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("usergit: transit %s: %w", op, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("usergit: transit %s: status %d", op, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("usergit: transit %s: decode: %w", op, err)
	}
	return nil
}
