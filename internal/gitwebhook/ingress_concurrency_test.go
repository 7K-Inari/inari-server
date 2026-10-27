package gitwebhook

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"testing"
)

// Burst of duplicate deliveries (GitHub retries, multi-replica deploys):
// every verified delivery appends (no loss), and the pipeline is safe
// under concurrency. Downstream idempotency (pr_url-guarded finalize) is
// covered by the completer tests.
func TestIngressConcurrentDuplicateDeliveries(t *testing.T) {
	e := newIngressEnv(t, true)
	body := fixture(t, "github_pr_merged.json")
	secret := e.secret(t)

	const n = 16
	var wg sync.WaitGroup
	statuses := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req, err := http.NewRequest(http.MethodPost, e.srv.URL+"/api/v1/webhooks/git/github", bytes.NewReader(body))
			if err != nil {
				t.Error(err)
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-GitHub-Event", "pull_request")
			req.Header.Set("X-Hub-Signature-256", sign(secret, body))
			resp, err := e.srv.Client().Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			statuses[idx] = resp.StatusCode
		}(i)
	}
	wg.Wait()
	for i, st := range statuses {
		if st != http.StatusAccepted {
			t.Errorf("delivery %d: status = %d, want 202", i, st)
		}
	}
	if len(e.outbox.events) != n {
		t.Errorf("outbox events = %d, want %d (no verified delivery may be lost)", len(e.outbox.events), n)
	}
}

// The finalizer's idempotency under redelivery is already covered; here
// the SECOND completer path errors first, then succeeds — the error must
// propagate (redelivery) and the retry must complete exactly once.
func TestFinalizerRetryAfterCompleterError(t *testing.T) {
	inst := &fakeCompleter{err: context.DeadlineExceeded}
	h := NewMergeFinalizer(inst, &fakeCompleter{}, nil)
	ev := mergeEvent(t, PRMergedPayload{PRURL: "u", MergeSHA: "s"})
	if err := h.Handle(context.Background(), ev); err == nil {
		t.Fatal("first delivery must error (redelivery)")
	}
	inst.err = nil
	inst.found = true
	if err := h.Handle(context.Background(), ev); err != nil {
		t.Fatalf("redelivery must succeed: %v", err)
	}
	if len(inst.calls) != 2 {
		t.Errorf("completer calls = %d, want 2", len(inst.calls))
	}
}
