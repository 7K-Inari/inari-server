package gitwebhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

var testSecret = []byte("test-webhook-secret")

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func sign(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func headers(event string, body, secret []byte) http.Header {
	h := http.Header{}
	h.Set("X-GitHub-Event", event)
	h.Set("X-Hub-Signature-256", sign(secret, body))
	return h
}

// Positive signature cases: a correctly signed delivery verifies.
func TestGitHubVerifySignatureValid(t *testing.T) {
	a := GitHubAdapter{}
	body := fixture(t, "github_pr_merged.json")
	if err := a.VerifySignature(headers("pull_request", body, testSecret), body, testSecret); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
}

// Negative signature cases: wrong secret, tampered body, missing header,
// malformed header values must all be rejected.
func TestGitHubVerifySignatureNegative(t *testing.T) {
	a := GitHubAdapter{}
	body := fixture(t, "github_pr_merged.json")

	cases := map[string]http.Header{
		"wrong secret": headers("pull_request", body, []byte("other-secret")),
		"missing header": func() http.Header {
			h := http.Header{}
			h.Set("X-GitHub-Event", "pull_request")
			return h
		}(),
		"missing sha256 prefix": func() http.Header {
			h := headers("pull_request", body, testSecret)
			mac := hmac.New(sha256.New, testSecret)
			mac.Write(body)
			h.Set("X-Hub-Signature-256", hex.EncodeToString(mac.Sum(nil)))
			return h
		}(),
		"non-hex digest": func() http.Header {
			h := headers("pull_request", body, testSecret)
			h.Set("X-Hub-Signature-256", "sha256=not-hex!!")
			return h
		}(),
		"empty header": func() http.Header {
			h := headers("pull_request", body, testSecret)
			h.Set("X-Hub-Signature-256", "")
			return h
		}(),
	}
	for name, h := range cases {
		if err := a.VerifySignature(h, body, testSecret); !errors.Is(err, ErrSignatureInvalid) {
			t.Errorf("%s: err = %v, want ErrSignatureInvalid", name, err)
		}
	}

	// A signature over the original body must not verify a tampered body.
	tampered := append([]byte{}, body...)
	tampered[len(tampered)/2] = 'X'
	if err := a.VerifySignature(headers("pull_request", body, testSecret), tampered, testSecret); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("tampered body: err = %v, want ErrSignatureInvalid", err)
	}
}

func TestGitHubParsePRMerged(t *testing.T) {
	a := GitHubAdapter{}
	body := fixture(t, "github_pr_merged.json")
	ev, err := a.ParseEvent(headers("pull_request", body, testSecret), body)
	if err != nil {
		t.Fatal(err)
	}
	if ev == nil || ev.Type != EventTypePRMerged {
		t.Fatalf("event = %+v, want pr_merged", ev)
	}
	if ev.Repo != "acme/team-a-gitops" {
		t.Errorf("repo = %q", ev.Repo)
	}
	want := &PRMerged{
		PRNumber:   17,
		MergeSHA:   "6dcb09b5b57875f334f61aebed695e2e4193db5e",
		BaseBranch: "main",
		PRURL:      "https://github.com/acme/team-a-gitops/pull/17",
	}
	if *ev.PRMerged != *want {
		t.Errorf("pr_merged = %+v, want %+v", ev.PRMerged, want)
	}
}

// A closed-but-unmerged PR is not a merge — ignored (nil event).
func TestGitHubParsePRClosedUnmerged(t *testing.T) {
	a := GitHubAdapter{}
	body := fixture(t, "github_pr_closed_unmerged.json")
	ev, err := a.ParseEvent(headers("pull_request", body, testSecret), body)
	if err != nil {
		t.Fatal(err)
	}
	if ev != nil {
		t.Errorf("event = %+v, want nil (not merged)", ev)
	}
}

// Non-closed pull_request actions (opened, synchronize, ...) are ignored.
func TestGitHubParsePROpenedIgnored(t *testing.T) {
	a := GitHubAdapter{}
	body := fixture(t, "github_pr_merged.json")
	body = []byte(replaceOnce(string(body), `"action": "closed"`, `"action": "opened"`))
	ev, err := a.ParseEvent(headers("pull_request", body, testSecret), body)
	if err != nil {
		t.Fatal(err)
	}
	if ev != nil {
		t.Errorf("event = %+v, want nil (opened)", ev)
	}
}

func TestGitHubParsePush(t *testing.T) {
	a := GitHubAdapter{}
	body := fixture(t, "github_push.json")
	ev, err := a.ParseEvent(headers("push", body, testSecret), body)
	if err != nil {
		t.Fatal(err)
	}
	if ev == nil || ev.Type != EventTypePush {
		t.Fatalf("event = %+v, want push", ev)
	}
	want := &Push{Branch: "main", HeadSHA: "827efc6d56897b048c772eb4087f854f46256132"}
	if ev.Repo != "acme/team-a-gitops" || *ev.Push != *want {
		t.Errorf("push = %+v repo %q, want %+v", ev.Push, ev.Repo, want)
	}
}

// Ping (hook provisioning check) and unsupported events are ignored.
func TestGitHubParsePingAndUnsupported(t *testing.T) {
	a := GitHubAdapter{}
	ping := fixture(t, "github_ping.json")
	ev, err := a.ParseEvent(headers("ping", ping, testSecret), ping)
	if err != nil || ev != nil {
		t.Errorf("ping: ev = %+v err = %v, want nil nil", ev, err)
	}
	ev, err = a.ParseEvent(headers("issues", ping, testSecret), ping)
	if err != nil || ev != nil {
		t.Errorf("issues: ev = %+v err = %v, want nil nil", ev, err)
	}
}

// Malformed payloads on a supported event are a 400-class parse error.
func TestGitHubParseMalformed(t *testing.T) {
	a := GitHubAdapter{}
	body := []byte(`{"action": "closed", "number": `)
	if _, err := a.ParseEvent(headers("pull_request", body, testSecret), body); err == nil {
		t.Fatal("want parse error for malformed JSON")
	}
}

// The registry resolves adapters by provider name; unknown providers miss.
func TestRegistry(t *testing.T) {
	a, ok := (Registry{}).For("github")
	if !ok || a.Name() != "github" {
		t.Errorf("github adapter = %v %v", a, ok)
	}
	if _, ok := (Registry{}).For("gitlab"); ok {
		t.Error("gitlab must not resolve yet (Phase 4)")
	}
}

func replaceOnce(s, old, new string) string {
	for i := 0; i+len(old) <= len(s); i++ {
		if s[i:i+len(old)] == old {
			return s[:i] + new + s[i+len(old):]
		}
	}
	return s
}
