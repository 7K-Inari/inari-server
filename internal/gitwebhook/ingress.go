package gitwebhook

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/types"
)

// RepoLookup resolves a delivery's repo slug to its registry row (the
// ingress has no org context — the row's webhook secret IS the credential).
type RepoLookup interface {
	FindGitRepoByRepo(ctx context.Context, q db.Querier, repo string, provider types.GitRepoProvider) (*types.TenantGitRepo, error)
}

// OutboxAppender appends one normalized event to the transactional outbox
// (implemented by audit.AppendOutbox in production).
type OutboxAppender interface {
	AppendOutbox(ctx context.Context, q db.Querier, orgID, eventType string, payload any) error
}

// Ingress is the webhook receive pipeline: adapter selection → repo
// resolution → secret load → signature verification → normalization →
// outbox. It carries no provider-specific logic (that lives in adapters).
type Ingress struct {
	q        db.Querier // pool; nil in unit tests (fakes ignore it)
	repos    RepoLookup
	secrets  *SecretStore
	outbox   OutboxAppender
	registry Registry
}

// NewIngress wires the pipeline. q is the DB pool (deliveries are appended
// outside an explicit TX — each is a single outbox row).
func NewIngress(q db.Querier, repos RepoLookup, secrets *SecretStore, outbox OutboxAppender) *Ingress {
	return &Ingress{q: q, repos: repos, secrets: secrets, outbox: outbox}
}

// Receive processes one delivery. The error return carries huma errors
// (401/404/400); accepted=false means a verified but non-actionable
// delivery (ping, unsupported event, non-merge PR action).
func (i *Ingress) Receive(ctx context.Context, provider string, hdr http.Header, body []byte) (eventType EventType, accepted bool, err error) {
	adapter, ok := i.registry.For(provider)
	if !ok {
		return "", false, huma.Error404NotFound("unknown git provider")
	}
	repoSlug, err := adapter.RepoHint(hdr, body)
	if err != nil {
		return "", false, huma.Error400BadRequest("malformed delivery: " + err.Error())
	}
	row, err := i.repos.FindGitRepoByRepo(ctx, i.q, repoSlug, types.GitRepoProvider(provider))
	if errors.Is(err, inventory.ErrRepoNotFound) {
		return "", false, huma.Error404NotFound("repo not registered")
	}
	if err != nil {
		return "", false, err
	}
	secret, err := i.secrets.Load(ctx, i.q, row.ID)
	if errors.Is(err, ErrWebhookNotProvisioned) {
		return "", false, huma.Error404NotFound("repo has no webhook provisioned")
	}
	if err != nil {
		return "", false, err
	}
	if err := adapter.VerifySignature(hdr, body, secret); err != nil {
		return "", false, huma.Error401Unauthorized("invalid signature")
	}
	ev, err := adapter.ParseEvent(hdr, body)
	if err != nil {
		return "", false, huma.Error400BadRequest("malformed delivery: " + err.Error())
	}
	if ev == nil {
		return "", false, nil
	}
	var payload any
	switch ev.Type {
	case EventTypePRMerged:
		payload = PRMergedPayload{
			Repo: ev.Repo, PRNumber: ev.PRMerged.PRNumber, MergeSHA: ev.PRMerged.MergeSHA,
			BaseBranch: ev.PRMerged.BaseBranch, PRURL: ev.PRMerged.PRURL,
		}
	case EventTypePush:
		payload = PushPayload{Repo: ev.Repo, Branch: ev.Push.Branch, HeadSHA: ev.Push.HeadSHA}
	default:
		return "", false, nil
	}
	if err := i.outbox.AppendOutbox(ctx, i.q, row.OrgID, string(ev.Type), payload); err != nil {
		return "", false, err
	}
	return ev.Type, true, nil
}

// Handler exposes the ingress REST surface.
type Handler struct {
	ing *Ingress
}

// NewHandler wires the REST handler. ing may be nil (export-openapi /
// disabled wiring): the route stays registered and answers 501.
func NewHandler(ing *Ingress) *Handler { return &Handler{ing: ing} }

// errDisabled is returned when the ingress is not wired (no DB/vault).
var errDisabled = huma.Error501NotImplemented("git webhook ingress disabled")

// RegisterRoutes mounts the webhook ingress. No Security spec: deliveries
// carry no bearer token — the per-repo HMAC secret is the credential
// (same model as the usergit OAuth callback's signed state).
func (h *Handler) RegisterRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "gitWebhookIngress",
		Method:      http.MethodPost,
		Path:        "/api/v1/webhooks/git/{provider}",
		Summary:     "Git provider webhook ingress (per-repo HMAC-authenticated)",
		// The body is consumed raw (HMAC over exact bytes) and parsed by
		// the provider adapter — schema validation must not run.
		SkipValidateBody: true,
	}, h.receive)
}

type receiveInput struct {
	Provider string `path:"provider"`
	RawBody  []byte `contentType:"application/json"`
	// Provider delivery headers (declared so huma forwards them; the
	// adapter decides which it needs). GitLab/Forgejo headers join here
	// with their adapters.
	HubSignature string `header:"X-Hub-Signature-256"`
	GitHubEvent  string `header:"X-GitHub-Event"`
	GitlabToken  string `header:"X-Gitlab-Token"`
	GitlabEvent  string `header:"X-Gitlab-Event"`
}

type receiveOutput struct {
	Status int `json:"-"`
	Body   struct {
		Accepted  bool   `json:"accepted"`
		EventType string `json:"eventType,omitempty"`
	}
}

func (h *Handler) receive(ctx context.Context, in *receiveInput) (*receiveOutput, error) {
	if h.ing == nil {
		return nil, errDisabled
	}
	hdr := http.Header{}
	if in.HubSignature != "" {
		hdr.Set("X-Hub-Signature-256", in.HubSignature)
	}
	if in.GitHubEvent != "" {
		hdr.Set("X-GitHub-Event", in.GitHubEvent)
	}
	if in.GitlabToken != "" {
		hdr.Set("X-Gitlab-Token", in.GitlabToken)
	}
	if in.GitlabEvent != "" {
		hdr.Set("X-Gitlab-Event", in.GitlabEvent)
	}
	eventType, accepted, err := h.ing.Receive(ctx, in.Provider, hdr, in.RawBody)
	if err != nil {
		return nil, err
	}
	out := &receiveOutput{Status: http.StatusAccepted}
	out.Body.Accepted = accepted
	out.Body.EventType = string(eventType)
	return out, nil
}
