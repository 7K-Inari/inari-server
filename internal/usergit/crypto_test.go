package usergit

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKEK(t *testing.T) *StaticKEK {
	t.Helper()
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	k, err := NewStaticKEK(key)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestCipherRoundTrip(t *testing.T) {
	c, err := NewCipher(testKEK(t))
	if err != nil {
		t.Fatal(err)
	}
	aad := "user_git_connections:ugc:123"
	dataEnc, dekEnc, err := c.Encrypt([]byte("refresh-token-secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(dataEnc), "refresh-token-secret") || strings.Contains(string(dekEnc), "refresh-token-secret") {
		t.Fatal("ciphertext contains plaintext")
	}
	plain, err := c.Decrypt(dataEnc, dekEnc, aad)
	if err != nil {
		t.Fatal(err)
	}
	defer Zero(plain)
	if string(plain) != "refresh-token-secret" {
		t.Fatalf("plaintext = %q", plain)
	}
}

func TestCipherWrongAADFailsOpaque(t *testing.T) {
	c, _ := NewCipher(testKEK(t))
	dataEnc, dekEnc, err := c.Encrypt([]byte("secret"), "user_git_connections:ugc:1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Decrypt(dataEnc, dekEnc, "user_git_connections:ugc:2"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("err = %v, want ErrDecrypt", err)
	}
}

func TestCipherTamperedCiphertext(t *testing.T) {
	c, _ := NewCipher(testKEK(t))
	dataEnc, dekEnc, err := c.Encrypt([]byte("secret"), "aad")
	if err != nil {
		t.Fatal(err)
	}
	dataEnc[len(dataEnc)-1] ^= 0xff
	if _, err := c.Decrypt(dataEnc, dekEnc, "aad"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("err = %v, want ErrDecrypt", err)
	}
}

func TestCipherWrongKEK(t *testing.T) {
	c1, _ := NewCipher(testKEK(t))
	c2, _ := NewCipher(testKEK(t))
	dataEnc, dekEnc, err := c1.Encrypt([]byte("secret"), "aad")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Decrypt(dataEnc, dekEnc, "aad"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("err = %v, want ErrDecrypt", err)
	}
}

func TestNewStaticKEKRejectsBadLength(t *testing.T) {
	if _, err := NewStaticKEK([]byte("short")); err == nil {
		t.Fatal("want error for short key")
	} else if strings.Contains(err.Error(), "short") {
		t.Fatal("error contains key material")
	}
}

func TestLoadStaticKEK(t *testing.T) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	enc := base64.StdEncoding.EncodeToString(key)

	t.Run("from usergit key file", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "kek")
		if err := os.WriteFile(f, []byte(enc+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("INARI_USERGIT_KEK_FILE", f)
		t.Setenv("INARI_CREDENTIAL_KEK_FILE", "")
		t.Setenv("INARI_USERGIT_KEK", "")
		t.Setenv("INARI_CREDENTIAL_KEK", "")
		got, err := LoadStaticKEK()
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(key) {
			t.Fatal("KEK mismatch")
		}
	})

	t.Run("falls back to credential KEK env", func(t *testing.T) {
		t.Setenv("INARI_USERGIT_KEK_FILE", "")
		t.Setenv("INARI_CREDENTIAL_KEK_FILE", "")
		t.Setenv("INARI_USERGIT_KEK", "")
		t.Setenv("INARI_CREDENTIAL_KEK", enc)
		got, err := LoadStaticKEK()
		if err != nil || string(got) != string(key) {
			t.Fatalf("got err=%v", err)
		}
	})

	t.Run("wrong length rejected without echoing material", func(t *testing.T) {
		t.Setenv("INARI_USERGIT_KEK_FILE", "")
		t.Setenv("INARI_CREDENTIAL_KEK_FILE", "")
		t.Setenv("INARI_USERGIT_KEK", base64.StdEncoding.EncodeToString([]byte("tiny")))
		t.Setenv("INARI_CREDENTIAL_KEK", "")
		_, err := LoadStaticKEK()
		if err == nil {
			t.Fatal("want error")
		}
		if strings.Contains(err.Error(), "tiny") {
			t.Fatal("error contains key material")
		}
	})

	t.Run("missing everywhere", func(t *testing.T) {
		t.Setenv("INARI_USERGIT_KEK_FILE", "")
		t.Setenv("INARI_CREDENTIAL_KEK_FILE", "")
		t.Setenv("INARI_USERGIT_KEK", "")
		t.Setenv("INARI_CREDENTIAL_KEK", "")
		if _, err := LoadStaticKEK(); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestTransitKEKRoundTrip(t *testing.T) {
	// Fake OpenBao transit: encrypt = base64(reverse(plaintext)) wrapped in a
	// vault:v1: blob; decrypt reverses it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "tok" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		switch {
		case strings.Contains(r.URL.Path, "/encrypt/"):
			raw, _ := base64.StdEncoding.DecodeString(in["plaintext"])
			for i, j := 0, len(raw)-1; i < j; i, j = i+1, j-1 {
				raw[i], raw[j] = raw[j], raw[i]
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{
				"ciphertext": "vault:v1:" + base64.StdEncoding.EncodeToString(raw)}})
		case strings.Contains(r.URL.Path, "/decrypt/"):
			ct := strings.TrimPrefix(in["ciphertext"], "vault:v1:")
			raw, _ := base64.StdEncoding.DecodeString(ct)
			for i, j := 0, len(raw)-1; i < j; i, j = i+1, j-1 {
				raw[i], raw[j] = raw[j], raw[i]
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{
				"plaintext": base64.StdEncoding.EncodeToString(raw)}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	kek, err := NewTransitKEK(srv.URL, "transit", "usergit", "tok", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCipher(kek)
	if err != nil {
		t.Fatal(err)
	}
	dataEnc, dekEnc, err := c.Encrypt([]byte("refresh-secret"), "aad")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(dekEnc), "vault:v1:") {
		t.Fatalf("dek_enc = %q, want vault blob", dekEnc)
	}
	plain, err := c.Decrypt(dataEnc, dekEnc, "aad")
	if err != nil {
		t.Fatal(err)
	}
	defer Zero(plain)
	if string(plain) != "refresh-secret" {
		t.Fatalf("plaintext = %q", plain)
	}

	// Unwrap failure maps to opaque ErrDecrypt.
	if _, err := c.Decrypt(dataEnc, []byte("vault:v1:!!!"), "aad"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("err = %v, want ErrDecrypt", err)
	}
}

func TestNewTransitKEKValidation(t *testing.T) {
	if _, err := NewTransitKEK("http://evil.example", "transit", "k", "tok", nil); err == nil {
		t.Fatal("http non-loopback must be rejected")
	}
	if _, err := NewTransitKEK("https://vault.example", "transit", "", "tok", nil); err == nil {
		t.Fatal("missing key name must fail")
	}
}
