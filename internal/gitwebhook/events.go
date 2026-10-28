// Package gitwebhook is the provider-agnostic git webhook ingress (parent
// plan §9 risk #1): signed deliveries arrive at
// POST /api/v1/webhooks/git/{provider}, per-provider adapters verify and
// normalize them, and subscribers consume only the normalized events via
// the transactional outbox — no provider-specific code outside adapters.
// The first subscriber is the PR-merge finalizer (closes the documented
// "app registers after PR merge" gap); the Fleet Manager subscribes later.
package gitwebhook

// EventType identifies a normalized webhook event. The values double as
// outbox event types (subjects inari.outbox.<type>).
type EventType string

const (
	// EventTypePRMerged: a pull request against a registered repo merged.
	EventTypePRMerged EventType = "git.webhook.pr_merged"
	// EventTypePush: a branch of a registered repo moved.
	EventTypePush EventType = "git.webhook.push"
)

// Event is the normalized, provider-agnostic form of one delivery.
// Exactly one payload field is set, per Type.
type Event struct {
	Type     EventType
	Repo     string // owner/name
	PRMerged *PRMerged
	Push     *Push
}

// PRMerged carries the facts of a merged pull request.
type PRMerged struct {
	PRNumber   int    `json:"prNumber"`
	MergeSHA   string `json:"mergeSha"`
	BaseBranch string `json:"baseBranch"`
	PRURL      string `json:"prUrl"`
}

// Push carries the new head of a moved branch.
type Push struct {
	Branch  string `json:"branch"`
	HeadSHA string `json:"headSha"`
}

// PRMergedPayload is the outbox payload for EventTypePRMerged.
type PRMergedPayload struct {
	Repo       string `json:"repo"`
	PRNumber   int    `json:"prNumber"`
	MergeSHA   string `json:"mergeSha"`
	BaseBranch string `json:"baseBranch"`
	PRURL      string `json:"prUrl"`
}

// PushPayload is the outbox payload for EventTypePush.
type PushPayload struct {
	Repo    string `json:"repo"`
	Branch  string `json:"branch"`
	HeadSHA string `json:"headSha"`
}
