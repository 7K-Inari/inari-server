package leaderlease

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// fakeStore implements the store seam with scripted behavior.
type fakeStore struct {
	mu          sync.Mutex
	acquireOK   []bool // scripted results; last one repeats when exhausted
	acquireErr  error
	renewOK     bool
	renewErr    error
	released    chan struct{}
	renewCalls  chan struct{}
	acquireCall chan struct{}
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		renewOK:     true,
		released:    make(chan struct{}, 1),
		renewCalls:  make(chan struct{}, 100),
		acquireCall: make(chan struct{}, 100),
	}
}

func (f *fakeStore) acquire(_ context.Context, _, _ string, _ time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	select {
	case f.acquireCall <- struct{}{}:
	default:
	}
	if f.acquireErr != nil {
		return false, f.acquireErr
	}
	if len(f.acquireOK) == 0 {
		return true, nil
	}
	ok := f.acquireOK[0]
	if len(f.acquireOK) > 1 {
		f.acquireOK = f.acquireOK[1:]
	}
	return ok, nil
}

func (f *fakeStore) renew(_ context.Context, _, _ string, _ time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	select {
	case f.renewCalls <- struct{}{}:
	default:
	}
	return f.renewOK, f.renewErr
}

func (f *fakeStore) release(_ context.Context, _, _ string) error {
	select {
	case f.released <- struct{}{}:
	default:
	}
	return nil
}

func (f *fakeStore) setRenew(ok bool, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.renewOK, f.renewErr = ok, err
}

func testConfig() Config {
	return Config{
		Holder:        "test-holder",
		TTL:           150 * time.Millisecond,
		RenewInterval: 20 * time.Millisecond,
		AcquireRetry:  10 * time.Millisecond,
	}
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestAcquireSucceedsWhenFree(t *testing.T) {
	l := NewWithStore(newFakeStore(), testConfig())
	lease, err := l.Acquire(context.Background(), "loop-a")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer func() { _ = lease.Release(context.Background()) }()
	select {
	case <-lease.Done():
		t.Fatal("lease Done closed while held")
	default:
	}
}

func TestAcquireRetriesUntilAvailable(t *testing.T) {
	fs := newFakeStore()
	fs.acquireOK = []bool{false, false, true}
	l := NewWithStore(fs, testConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	lease, err := l.Acquire(ctx, "loop-a")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer func() { _ = lease.Release(context.Background()) }()
}

func TestAcquireContextCancelled(t *testing.T) {
	fs := newFakeStore()
	fs.acquireOK = []bool{false}
	l := NewWithStore(fs, testConfig())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := l.Acquire(ctx, "loop-a"); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestRenewKeepsLease(t *testing.T) {
	fs := newFakeStore()
	l := NewWithStore(fs, testConfig())
	lease, err := l.Acquire(context.Background(), "loop-a")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer func() { _ = lease.Release(context.Background()) }()
	// Several renew intervals pass with renew succeeding: lease stays held.
	time.Sleep(5 * testConfig().RenewInterval)
	select {
	case <-lease.Done():
		t.Fatal("lease lost despite successful renewals")
	default:
	}
	select {
	case <-fs.renewCalls:
	default:
		t.Fatal("expected renewal attempts")
	}
}

func TestRenewMissLosesLease(t *testing.T) {
	fs := newFakeStore()
	l := NewWithStore(fs, testConfig())
	lease, err := l.Acquire(context.Background(), "loop-a")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	fs.setRenew(false, nil) // another holder took the row
	waitClosed(t, lease.Done(), "lease loss")
	if !errors.Is(lease.Err(), ErrLeaseLost) {
		t.Fatalf("want ErrLeaseLost, got %v", lease.Err())
	}
}

func TestRenewErrorsLoseLeaseAfterTTL(t *testing.T) {
	fs := newFakeStore()
	l := NewWithStore(fs, testConfig())
	lease, err := l.Acquire(context.Background(), "loop-a")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	fs.setRenew(false, errors.New("db down"))
	// Transient errors do not immediately forfeit the lease...
	select {
	case <-lease.Done():
		t.Fatal("lease lost on first transient renew error")
	case <-time.After(testConfig().TTL / 2):
	}
	// ...but failing to renew past the TTL does.
	waitClosed(t, lease.Done(), "lease loss after TTL")
	if !errors.Is(lease.Err(), ErrLeaseLost) {
		t.Fatalf("want ErrLeaseLost, got %v", lease.Err())
	}
}

func TestRelease(t *testing.T) {
	fs := newFakeStore()
	l := NewWithStore(fs, testConfig())
	lease, err := l.Acquire(context.Background(), "loop-a")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if err := lease.Release(context.Background()); err != nil {
		t.Fatalf("release: %v", err)
	}
	waitClosed(t, lease.Done(), "Done after release")
	if lease.Err() != nil {
		t.Fatalf("voluntary release must not set Err, got %v", lease.Err())
	}
	waitClosed(t, fs.released, "store release call")
	// Renewal must stop after release: drain, then expect silence.
	for len(fs.renewCalls) > 0 {
		<-fs.renewCalls
	}
	time.Sleep(3 * testConfig().RenewInterval)
	select {
	case <-fs.renewCalls:
		t.Fatal("renewal continued after release")
	default:
	}
}

func TestRunCancelsFnOnLeaseLoss(t *testing.T) {
	fs := newFakeStore()
	l := NewWithStore(fs, testConfig())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan context.Context, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		Run(ctx, l, "loop-a", func(lctx context.Context) {
			started <- lctx
			<-lctx.Done()
		}, slog.Default())
	}()
	lctx := <-started
	fs.setRenew(false, nil)
	waitClosed(t, lctx.Done(), "fn context cancellation on lease loss")
	cancel()
	waitClosed(t, done, "Run return")
}

func TestRunReacquiresAfterLoss(t *testing.T) {
	fs := newFakeStore()
	cfg := testConfig()
	l := NewWithStore(fs, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runs := make(chan struct{}, 4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		Run(ctx, l, "loop-a", func(lctx context.Context) {
			runs <- struct{}{}
			<-lctx.Done()
		}, slog.Default())
	}()
	<-runs
	// Lose the lease, then let the re-acquire succeed and run fn a 2nd time.
	fs.setRenew(false, nil)
	select {
	case <-runs:
	case <-time.After(3 * time.Second):
		t.Fatal("fn did not run again after re-acquire")
	}
	cancel()
	waitClosed(t, done, "Run return")
}

func TestRunStopsOnContextCancel(t *testing.T) {
	fs := newFakeStore()
	fs.acquireOK = []bool{false} // never acquired
	l := NewWithStore(fs, testConfig())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		Run(ctx, l, "loop-a", func(context.Context) {
			t.Error("fn must not run while lease is unacquired")
		}, slog.Default())
	}()
	cancel()
	waitClosed(t, done, "Run return")
}
