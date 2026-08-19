// Senders deliver notification messages to endpoint kinds (plan §5.2 v1:
// Slack incoming webhooks + generic signed webhooks).
package notifications

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/7K-Inari/inari-server/internal/types"
)

// Message is one notification to deliver.
type Message struct {
	Text      string          `json:"text"`
	EventType string          `json:"eventType"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

// Sender delivers one message to one endpoint.
type Sender interface {
	Send(ctx context.Context, ep *types.NotificationEndpoint, msg Message) error
}

func defaultHTTPClient(c *http.Client) *http.Client {
	if c != nil {
		if c.Timeout == 0 {
			copy := *c
			copy.Timeout = 10 * time.Second
			return &copy
		}
		return c
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		// Never follow redirects: a public URL must not bounce the control
		// plane into an internal address (SSRF).
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// SlackSender POSTs {"text": ...} to a Slack incoming-webhook URL.
type SlackSender struct {
	client *http.Client
}

func NewSlackSender(client *http.Client) *SlackSender {
	return &SlackSender{client: defaultHTTPClient(client)}
}

func (s *SlackSender) Send(ctx context.Context, ep *types.NotificationEndpoint, msg Message) error {
	body, err := json.Marshal(map[string]string{"text": msg.Text})
	if err != nil {
		return fmt.Errorf("notifications: slack marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notifications: slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("notifications: slack post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("notifications: slack post: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// WebhookSender POSTs a JSON envelope to a generic endpoint, signing the
// body with HMAC-SHA256 when the endpoint has a secret.
type WebhookSender struct {
	client *http.Client
	now    func() time.Time
}

func NewWebhookSender(client *http.Client) *WebhookSender {
	return &WebhookSender{client: defaultHTTPClient(client), now: time.Now}
}

func (s *WebhookSender) Send(ctx context.Context, ep *types.NotificationEndpoint, msg Message) error {
	body, err := json.Marshal(map[string]any{
		"event":   msg.EventType,
		"text":    msg.Text,
		"payload": msg.Payload,
		"sentAt":  s.now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("notifications: webhook marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notifications: webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if ep.Secret != "" {
		mac := hmac.New(sha256.New, []byte(ep.Secret))
		mac.Write(body)
		req.Header.Set("X-Inari-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("notifications: webhook post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("notifications: webhook post: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// SenderFor returns the sender matching the endpoint kind.
func SenderFor(kind string, slack *SlackSender, webhook *WebhookSender) (Sender, error) {
	switch kind {
	case types.NotificationKindSlack:
		return slack, nil
	case types.NotificationKindWebhook:
		return webhook, nil
	}
	return nil, fmt.Errorf("notifications: unknown endpoint kind %q", kind)
}
