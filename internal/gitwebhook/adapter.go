package gitwebhook

import (
	"errors"
	"net/http"
)

// ErrSignatureInvalid is returned when a delivery's signature is missing,
// malformed, or does not match the repo's webhook secret (401-class).
var ErrSignatureInvalid = errors.New("gitwebhook: invalid signature")

// Adapter verifies and parses one provider's webhook deliveries. Adding a
// provider (GitLab: X-Gitlab-Token + repo-identity check; Forgejo/Gitea:
// GitHub-style HMAC + near-GitHub schema) means implementing this
// interface and registering it — ingress and subscribers stay untouched.
type Adapter interface {
	// Name is the provider key used in the route path and the registry.
	Name() string
	// RepoHint extracts the repo slug from an UNVERIFIED delivery, used
	// only to resolve which webhook secret authenticates it. The value is
	// never trusted before VerifySignature passes.
	RepoHint(h http.Header, body []byte) (string, error)
	// VerifySignature authenticates the raw delivery against the repo's
	// webhook secret. Any failure is ErrSignatureInvalid (the cause is
	// never distinguished to callers).
	VerifySignature(h http.Header, body, secret []byte) error
	// ParseEvent normalizes the delivery. A nil event (with nil error)
	// means "valid but not actionable" — ping, unsupported event type,
	// non-merge PR actions — answered 204 by the ingress.
	ParseEvent(h http.Header, body []byte) (*Event, error)
}

// Registry resolves adapters by provider name.
type Registry struct{}

// For returns the adapter for provider ("github", ...).
func (Registry) For(provider string) (Adapter, bool) {
	switch provider {
	case "github":
		return GitHubAdapter{}, true
	default:
		return nil, false
	}
}
