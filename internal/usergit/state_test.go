package usergit

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func testStateManager(t *testing.T) *StateManager {
	t.Helper()
	m, err := NewStateManager([]byte("test-state-key-32-bytes-padded!!!"), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPKCEVerifierChallenge(t *testing.T) {
	v, err := NewCodeVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 43 {
		t.Fatalf("verifier len = %d, want 43", len(v))
	}
	sum := sha256.Sum256([]byte(v))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if got := CodeChallengeS256(v); got != want {
		t.Fatalf("challenge = %q, want %q", got, want)
	}
}

func TestStateRoundTrip(t *testing.T) {
	m := testStateManager(t)
	state, err := m.Issue("org:1", "user-1", "github", "https://ghe.example/api/v3", "verifier-abc")
	if err != nil {
		t.Fatal(err)
	}
	p, err := m.Validate(state)
	if err != nil {
		t.Fatal(err)
	}
	if p.OrgID != "org:1" || p.UserSub != "user-1" || p.Provider != "github" ||
		p.APIBase != "https://ghe.example/api/v3" || p.CodeVerifier != "verifier-abc" {
		t.Fatalf("payload = %+v", p)
	}
}

func TestStateSingleUse(t *testing.T) {
	m := testStateManager(t)
	state, err := m.Issue("org:1", "user-1", "github", "", "v")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Validate(state); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Validate(state); !errors.Is(err, ErrStateInvalid) {
		t.Fatalf("replay: err = %v, want ErrStateInvalid", err)
	}
}

func TestStateTamperedSignature(t *testing.T) {
	m := testStateManager(t)
	state, err := m.Issue("org:1", "user-1", "github", "", "v")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(state, ".")
	// Flip a payload byte; the signature no longer matches.
	raw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	raw[0] ^= 0xff
	tampered := base64.RawURLEncoding.EncodeToString(raw) + "." + parts[1]
	if _, err := m.Validate(tampered); !errors.Is(err, ErrStateInvalid) {
		t.Fatalf("err = %v, want ErrStateInvalid", err)
	}
	// Truncated/garbage states.
	for _, bad := range []string{"", "nosig", "a.b.c", "!!!.!!!"} {
		if _, err := m.Validate(bad); !errors.Is(err, ErrStateInvalid) {
			t.Errorf("state %q: err = %v, want ErrStateInvalid", bad, err)
		}
	}
}

func TestStateWrongKey(t *testing.T) {
	m1 := testStateManager(t)
	m2, _ := NewStateManager([]byte("different-key-different-key!!!!"), 10*time.Minute)
	state, err := m1.Issue("org:1", "user-1", "github", "", "v")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m2.Validate(state); !errors.Is(err, ErrStateInvalid) {
		t.Fatalf("err = %v, want ErrStateInvalid", err)
	}
}

func TestStateExpired(t *testing.T) {
	m := testStateManager(t)
	now := time.Now()
	m.now = func() time.Time { return now }
	state, err := m.Issue("org:1", "user-1", "github", "", "v")
	if err != nil {
		t.Fatal(err)
	}
	m.now = func() time.Time { return now.Add(11 * time.Minute) }
	if _, err := m.Validate(state); !errors.Is(err, ErrStateInvalid) {
		t.Fatalf("err = %v, want ErrStateInvalid", err)
	}
}

func TestStateUnknownNonce(t *testing.T) {
	// A validly-signed state whose nonce was never registered (e.g. issued
	// by another replica with the same key) must still fail: the nonce
	// table is the single-use guarantee.
	m := testStateManager(t)
	state, err := m.Issue("org:1", "user-1", "github", "", "v")
	if err != nil {
		t.Fatal(err)
	}
	m2, _ := NewStateManager([]byte("test-state-key-32-bytes-padded!!!"), 10*time.Minute)
	if _, err := m2.Validate(state); !errors.Is(err, ErrStateInvalid) {
		t.Fatalf("err = %v, want ErrStateInvalid", err)
	}
}
