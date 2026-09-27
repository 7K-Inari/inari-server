package cryptoenvelope

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func testCipher(t *testing.T) *Cipher {
	t.Helper()
	kek := make([]byte, KeySize)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	c, err := New(kek)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRoundTrip(t *testing.T) {
	c := testCipher(t)
	dataEnc, dekEnc, err := c.Encrypt([]byte("user-token-123"), []byte("agent_command_credentials:cred:1"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Contains(dataEnc, []byte("user-token-123")) || bytes.Contains(dekEnc, []byte("user-token-123")) {
		t.Fatal("ciphertext contains plaintext")
	}
	got, err := c.Decrypt(dataEnc, dekEnc, []byte("agent_command_credentials:cred:1"))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != "user-token-123" {
		t.Fatalf("round trip = %q", got)
	}
}

func TestWrongKEKFails(t *testing.T) {
	c1 := testCipher(t)
	c2 := testCipher(t)
	dataEnc, dekEnc, err := c1.Encrypt([]byte("secret"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Decrypt(dataEnc, dekEnc, []byte("aad")); err == nil {
		t.Fatal("decrypt under a different KEK succeeded")
	}
}

// AAD binds ciphertext to its row identity: a ciphertext transplanted to
// another row (different AAD) must not decrypt.
func TestAADMismatchFails(t *testing.T) {
	c := testCipher(t)
	dataEnc, dekEnc, err := c.Encrypt([]byte("secret"), []byte("table:cred:1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Decrypt(dataEnc, dekEnc, []byte("table:cred:2")); err == nil {
		t.Fatal("decrypt with transplanted AAD succeeded")
	}
}

func TestNewRejectsBadKeySize(t *testing.T) {
	if _, err := New([]byte("short")); err == nil {
		t.Fatal("short KEK accepted")
	}
}

func TestLoadKEK(t *testing.T) {
	kek := make([]byte, KeySize)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(kek)

	t.Run("from file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "kek")
		if err := os.WriteFile(path, []byte(encoded+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("INARI_CREDENTIAL_KEK_FILE", path)
		t.Setenv("INARI_CREDENTIAL_KEK", "")
		got, err := LoadKEK()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, kek) {
			t.Fatal("KEK from file mismatch")
		}
	})
	t.Run("from env", func(t *testing.T) {
		t.Setenv("INARI_CREDENTIAL_KEK_FILE", "")
		t.Setenv("INARI_CREDENTIAL_KEK", encoded)
		got, err := LoadKEK()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, kek) {
			t.Fatal("KEK from env mismatch")
		}
	})
	t.Run("missing", func(t *testing.T) {
		t.Setenv("INARI_CREDENTIAL_KEK_FILE", "")
		t.Setenv("INARI_CREDENTIAL_KEK", "")
		if _, err := LoadKEK(); err == nil {
			t.Fatal("missing KEK accepted")
		}
	})
	t.Run("bad length", func(t *testing.T) {
		t.Setenv("INARI_CREDENTIAL_KEK_FILE", "")
		t.Setenv("INARI_CREDENTIAL_KEK", base64.StdEncoding.EncodeToString([]byte("short")))
		if _, err := LoadKEK(); err == nil {
			t.Fatal("short KEK accepted")
		}
	})
}

func TestZero(t *testing.T) {
	b := []byte("sensitive")
	Zero(b)
	if !bytes.Equal(b, make([]byte, len(b))) {
		t.Fatal("Zero did not wipe")
	}
}
