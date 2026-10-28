package gitwebhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// GitHubAdapter verifies X-Hub-Signature-256 (HMAC-SHA256 over the raw
// body, hex-encoded with a "sha256=" prefix) and normalizes pull_request
// and push deliveries. The header scheme mirrors the server's own outbound
// signing convention (notifications.X-Inari-Signature).
type GitHubAdapter struct{}

func (GitHubAdapter) Name() string { return "github" }

// VerifySignature implements Adapter.
func (GitHubAdapter) VerifySignature(h http.Header, body, secret []byte) error {
	sig := h.Get("X-Hub-Signature-256")
	digest, ok := strings.CutPrefix(sig, "sha256=")
	if !ok || digest == "" {
		return ErrSignatureInvalid
	}
	got, err := hex.DecodeString(digest)
	if err != nil {
		return ErrSignatureInvalid
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	if !hmac.Equal(got, mac.Sum(nil)) {
		return ErrSignatureInvalid
	}
	return nil
}

// ParseEvent implements Adapter: pull_request (closed+merged) → pr_merged,
// push → push; ping, other PR actions, and unsupported events are ignored.
func (GitHubAdapter) ParseEvent(h http.Header, body []byte) (*Event, error) {
	switch h.Get("X-GitHub-Event") {
	case "pull_request":
		var p struct {
			Action string `json:"action"`
			Number int    `json:"number"`
			PR     struct {
				HTMLURL  string  `json:"html_url"`
				Merged   bool    `json:"merged"`
				MergeSHA *string `json:"merge_commit_sha"`
				Base     struct {
					Ref string `json:"ref"`
				} `json:"base"`
			} `json:"pull_request"`
			Repo struct {
				FullName string `json:"full_name"`
			} `json:"repository"`
		}
		if err := json.Unmarshal(body, &p); err != nil {
			return nil, fmt.Errorf("gitwebhook github: parse pull_request: %w", err)
		}
		if p.Action != "closed" || !p.PR.Merged || p.PR.MergeSHA == nil {
			return nil, nil
		}
		return &Event{
			Type: EventTypePRMerged,
			Repo: p.Repo.FullName,
			PRMerged: &PRMerged{
				PRNumber:   p.Number,
				MergeSHA:   *p.PR.MergeSHA,
				BaseBranch: p.PR.Base.Ref,
				PRURL:      p.PR.HTMLURL,
			},
		}, nil
	case "push":
		var p struct {
			Ref   string `json:"ref"`
			After string `json:"after"`
			Repo  struct {
				FullName string `json:"full_name"`
			} `json:"repository"`
		}
		if err := json.Unmarshal(body, &p); err != nil {
			return nil, fmt.Errorf("gitwebhook github: parse push: %w", err)
		}
		branch, ok := strings.CutPrefix(p.Ref, "refs/heads/")
		if !ok || branch == "" {
			// Tag pushes and other ref updates are not actionable.
			return nil, nil
		}
		return &Event{
			Type: EventTypePush,
			Repo: p.Repo.FullName,
			Push: &Push{Branch: branch, HeadSHA: p.After},
		}, nil
	default:
		// ping, issues, ... — valid but not actionable.
		return nil, nil
	}
}

// RepoHint implements Adapter.
func (GitHubAdapter) RepoHint(_ http.Header, body []byte) (string, error) {
	var p struct {
		Repo struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return "", fmt.Errorf("gitwebhook github: parse repository: %w", err)
	}
	if p.Repo.FullName == "" {
		return "", fmt.Errorf("gitwebhook github: no repository.full_name")
	}
	return p.Repo.FullName, nil
}
