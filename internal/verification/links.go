package verification

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var workflowNamePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)

// RunAttempt contains non-secret Workflow identity used for external links.
type RunAttempt struct {
	RunID             string
	Attempt           int
	WorkflowName      string
	WorkflowNamespace string
	WorkflowUID       string
	ClusterID         string
	LinksExpireAt     *time.Time
}

// RunLinks contains server-built external Argo UI deep links.
type RunLinks struct {
	Workflow  string `json:"workflow"`
	Logs      string `json:"logs"`
	Artifacts string `json:"artifacts"`
}

func BuildRunLinks(baseURL string, attempt *RunAttempt, now time.Time) (*RunLinks, error) {
	if baseURL == "" || attempt == nil || attempt.LinksExpireAt == nil || !now.Before(*attempt.LinksExpireAt) {
		return nil, nil
	}
	if !workflowNamePattern.MatchString(attempt.WorkflowName) || !workflowNamePattern.MatchString(attempt.WorkflowNamespace) || attempt.WorkflowUID == "" {
		return nil, errors.New("unsafe or incomplete Workflow identity")
	}
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("Argo UI base URL must be HTTPS without credentials, query, or fragment")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/workflows/" + attempt.WorkflowNamespace + "/" + attempt.WorkflowName
	workflowURL := *base
	logsURL := *base
	logsURL.RawQuery = "tab=logs"
	artifactsURL := *base
	artifactsURL.RawQuery = "tab=artifacts"
	return &RunLinks{Workflow: workflowURL.String(), Logs: logsURL.String(), Artifacts: artifactsURL.String()}, nil
}
