package notifications

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestSlackSenderBodyShape(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ep := &types.NotificationEndpoint{Kind: types.NotificationKindSlack, URL: srv.URL}
	err := NewSlackSender(nil).Send(context.Background(), ep, Message{Text: "hello", EventType: "approval.requested"})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got["text"] != "hello" {
		t.Fatalf("unexpected slack body: %s", body)
	}
	if len(got) != 1 {
		t.Fatalf("slack body must contain only text: %s", body)
	}
}

func TestSlackSenderErrorOn500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	ep := &types.NotificationEndpoint{Kind: types.NotificationKindSlack, URL: srv.URL}
	err := NewSlackSender(nil).Send(context.Background(), ep, Message{Text: "x"})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected status error, got %v", err)
	}
}

func TestWebhookSenderEnvelopeAndSignature(t *testing.T) {
	var body []byte
	var sig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		sig = r.Header.Get("X-Inari-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ep := &types.NotificationEndpoint{Kind: types.NotificationKindWebhook, URL: srv.URL, Secret: "s3cr3t"}
	msg := Message{Text: "hi", EventType: "approval.requested", Payload: json.RawMessage(`{"orgId":"org:1"}`)}
	if err := NewWebhookSender(nil).Send(context.Background(), ep, msg); err != nil {
		t.Fatal(err)
	}
	var env struct {
		Event   string          `json:"event"`
		Text    string          `json:"text"`
		Payload json.RawMessage `json:"payload"`
		SentAt  string          `json:"sentAt"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	if env.Event != "approval.requested" || env.Text != "hi" || env.SentAt == "" {
		t.Fatalf("bad envelope: %s", body)
	}
	if string(env.Payload) != `{"orgId":"org:1"}` {
		t.Fatalf("bad payload: %s", env.Payload)
	}
	mac := hmac.New(sha256.New, []byte("s3cr3t"))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if sig != want {
		t.Fatalf("signature mismatch: got %q want %q", sig, want)
	}
}

func TestWebhookSenderNoSecretNoSignature(t *testing.T) {
	var sig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sig = r.Header.Get("X-Inari-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	ep := &types.NotificationEndpoint{Kind: types.NotificationKindWebhook, URL: srv.URL}
	if err := NewWebhookSender(nil).Send(context.Background(), ep, Message{Text: "x"}); err != nil {
		t.Fatal(err)
	}
	if sig != "" {
		t.Fatalf("expected no signature header, got %q", sig)
	}
}

func TestWebhookSenderErrorOn500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	ep := &types.NotificationEndpoint{Kind: types.NotificationKindWebhook, URL: srv.URL}
	err := NewWebhookSender(nil).Send(context.Background(), ep, Message{Text: "x"})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected status error, got %v", err)
	}
}
