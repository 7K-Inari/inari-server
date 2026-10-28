package gitwebhook

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

type fakeCompleter struct {
	found bool
	err   error
	calls []completeCall
}

type completeCall struct {
	orgID, prURL, mergeSHA string
}

func (f *fakeCompleter) FinalizePRMerge(_ context.Context, orgID, prURL, mergeSHA string) (bool, error) {
	f.calls = append(f.calls, completeCall{orgID, prURL, mergeSHA})
	return f.found, f.err
}

func mergeEvent(t *testing.T, p PRMergedPayload) *types.OutboxEvent {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return &types.OutboxEvent{OrgID: "org:1", EventType: string(EventTypePRMerged), Payload: raw}
}

func TestFinalizerCompletesInstance(t *testing.T) {
	inst := &fakeCompleter{found: true}
	addons := &fakeCompleter{}
	h := NewMergeFinalizer(inst, addons, nil)
	err := h.Handle(context.Background(), mergeEvent(t, PRMergedPayload{
		Repo: "acme/state", PRNumber: 17, MergeSHA: "abc", BaseBranch: "main",
		PRURL: "https://github.com/acme/state/pull/17",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(inst.calls) != 1 {
		t.Fatalf("instance calls = %d, want 1", len(inst.calls))
	}
	c := inst.calls[0]
	if c.orgID != "org:1" || c.prURL != "https://github.com/acme/state/pull/17" || c.mergeSHA != "abc" {
		t.Errorf("call = %+v", c)
	}
	if len(addons.calls) != 0 {
		t.Error("matched instance must short-circuit the addon completer")
	}
}

func TestFinalizerFallsThroughToAddon(t *testing.T) {
	inst := &fakeCompleter{found: false}
	addons := &fakeCompleter{found: true}
	h := NewMergeFinalizer(inst, addons, nil)
	if err := h.Handle(context.Background(), mergeEvent(t, PRMergedPayload{PRURL: "u", MergeSHA: "s"})); err != nil {
		t.Fatal(err)
	}
	if len(inst.calls) != 1 || len(addons.calls) != 1 {
		t.Errorf("calls = %d/%d, want 1/1", len(inst.calls), len(addons.calls))
	}
}

// No row awaiting the PR (already finalized, or the PR isn't ours) is an
// ack, not an error — the status stream remains the fallback.
func TestFinalizerNoMatchIsAck(t *testing.T) {
	h := NewMergeFinalizer(&fakeCompleter{}, &fakeCompleter{}, nil)
	if err := h.Handle(context.Background(), mergeEvent(t, PRMergedPayload{PRURL: "u", MergeSHA: "s"})); err != nil {
		t.Errorf("err = %v, want nil (idempotent ack)", err)
	}
}

// Completer errors propagate so the outbox consumer redelivers.
func TestFinalizerErrorRedelivers(t *testing.T) {
	boom := errors.New("boom")
	h := NewMergeFinalizer(&fakeCompleter{err: boom}, &fakeCompleter{}, nil)
	if err := h.Handle(context.Background(), mergeEvent(t, PRMergedPayload{PRURL: "u", MergeSHA: "s"})); !errors.Is(err, boom) {
		t.Errorf("err = %v, want boom", err)
	}
}

// A merge event without a PR URL can match nothing — acked without calls.
func TestFinalizerEmptyPRURL(t *testing.T) {
	inst := &fakeCompleter{}
	h := NewMergeFinalizer(inst, &fakeCompleter{}, nil)
	if err := h.Handle(context.Background(), mergeEvent(t, PRMergedPayload{MergeSHA: "s"})); err != nil {
		t.Fatal(err)
	}
	if len(inst.calls) != 0 {
		t.Error("no PR URL must not reach completers")
	}
}

// Malformed payloads error (the outbox machinery dead-letters them).
func TestFinalizerMalformedPayload(t *testing.T) {
	h := NewMergeFinalizer(&fakeCompleter{}, &fakeCompleter{}, nil)
	err := h.Handle(context.Background(), &types.OutboxEvent{EventType: string(EventTypePRMerged), Payload: json.RawMessage(`{`)})
	if err == nil {
		t.Fatal("want error for malformed payload")
	}
}

func TestFinalizerEventTypes(t *testing.T) {
	h := NewMergeFinalizer(nil, nil, nil)
	types := h.EventTypes()
	if len(types) != 1 || types[0] != string(EventTypePRMerged) {
		t.Errorf("EventTypes = %v", types)
	}
}
