// OAuth state + PKCE for the user git connect flow (W4). State is a
// stateless HMAC-SHA256-signed payload binding (org, user, provider,
// apiBase, PKCE verifier) plus a single-use server-side nonce held in
// memory: the signature proves the platform issued the state, the nonce
// table makes each state usable exactly once and bounds its lifetime.
//
// Limitation (ADR-0012): the nonce table is per-process, so a multi-replica
// deployment can strand in-flight flows when the callback lands on a
// different pod. The failure mode is a safe re-auth, never a bypass.
package usergit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ErrStateInvalid is returned for any state validation failure (bad
// signature, expiry, unknown or replayed nonce, malformed payload).
var ErrStateInvalid = errors.New("usergit: invalid oauth state")

var b64url = base64.RawURLEncoding

// StatePayload is the signed content of an OAuth state parameter.
type StatePayload struct {
	OrgID        string `json:"org"`
	UserSub      string `json:"sub"`
	Provider     string `json:"provider"`
	APIBase      string `json:"apiBase,omitempty"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"cv"`
	ExpiresAt    int64  `json:"exp"`
}

// StateManager issues and validates HMAC-signed, single-use OAuth states.
type StateManager struct {
	key    []byte
	ttl    time.Duration
	now    func() time.Time
	mu     sync.Mutex
	nonces map[string]time.Time
}

// NewStateManager builds a manager; key is the HMAC secret (32 bytes
// recommended), ttl bounds state lifetime (e.g. 10 minutes).
func NewStateManager(key []byte, ttl time.Duration) (*StateManager, error) {
	if len(key) == 0 {
		return nil, errors.New("usergit: state key required")
	}
	if ttl <= 0 {
		return nil, errors.New("usergit: state TTL must be positive")
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &StateManager{key: k, ttl: ttl, now: time.Now, nonces: map[string]time.Time{}}, nil
}

// NewCodeVerifier returns a 43-char base64url PKCE verifier (RFC 7636).
func NewCodeVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("usergit: pkce verifier: %w", err)
	}
	return b64url.EncodeToString(b), nil
}

// CodeChallengeS256 derives the S256 PKCE challenge from a verifier.
func CodeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return b64url.EncodeToString(sum[:])
}

// Issue mints a signed state for the flow and registers its nonce.
func (m *StateManager) Issue(orgID, userSub, provider, apiBase, codeVerifier string) (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("usergit: state nonce: %w", err)
	}
	exp := m.now().Add(m.ttl)
	p := StatePayload{
		OrgID:        orgID,
		UserSub:      userSub,
		Provider:     provider,
		APIBase:      apiBase,
		Nonce:        b64url.EncodeToString(nonce),
		CodeVerifier: codeVerifier,
		ExpiresAt:    exp.Unix(),
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("usergit: state marshal: %w", err)
	}
	m.mu.Lock()
	m.nonces[p.Nonce] = exp
	m.sweepLocked(m.now())
	m.mu.Unlock()
	return b64url.EncodeToString(raw) + "." + b64url.EncodeToString(m.sign(raw)), nil
}

// Validate verifies the signature and expiry and consumes the nonce, so a
// state validates at most once. Any failure is ErrStateInvalid.
func (m *StateManager) Validate(state string) (*StatePayload, error) {
	raw64, sig64, ok := strings.Cut(state, ".")
	if !ok {
		return nil, ErrStateInvalid
	}
	raw, err := b64url.DecodeString(raw64)
	if err != nil {
		return nil, ErrStateInvalid
	}
	sig, err := b64url.DecodeString(sig64)
	if err != nil {
		return nil, ErrStateInvalid
	}
	if !hmac.Equal(sig, m.sign(raw)) {
		return nil, ErrStateInvalid
	}
	var p StatePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, ErrStateInvalid
	}
	now := m.now()
	if p.OrgID == "" || p.UserSub == "" || p.Provider == "" || p.Nonce == "" || p.CodeVerifier == "" {
		return nil, ErrStateInvalid
	}
	if now.Unix() >= p.ExpiresAt {
		return nil, ErrStateInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.nonces[p.Nonce]; !ok {
		return nil, ErrStateInvalid
	}
	delete(m.nonces, p.Nonce)
	return &p, nil
}

func (m *StateManager) sign(raw []byte) []byte {
	h := hmac.New(sha256.New, m.key)
	h.Write(raw)
	return h.Sum(nil)
}

// sweepLocked drops expired nonces; called under m.mu on Issue.
func (m *StateManager) sweepLocked(now time.Time) {
	for n, exp := range m.nonces {
		if now.After(exp) {
			delete(m.nonces, n)
		}
	}
}
