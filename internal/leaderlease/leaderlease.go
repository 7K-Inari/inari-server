// Package leaderlease provides DB-backed leader election for the control
// plane's singleton background loops (ADR-0011): exactly one replica drives
// each gated loop at a time, with failover bounded by the lease TTL. It is
// deliberately backed by Postgres (leader_leases table) rather than a k8s
// Lease — the server has no k8s API client/RBAC — and a pod death frees the
// lease once the row expires.
package leaderlease

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/7K-Inari/inari-server/internal/db"
)

// ErrLeaseLost is set on Lease.Err when leadership was lost involuntarily
// (renewal miss, or renewal impossible for longer than the TTL).
var ErrLeaseLost = errors.New("leaderlease: lease lost")

// Leaser acquires named, mutually-exclusive leadership grants.
type Leaser interface {
	// Acquire blocks (retrying on contention and transient DB errors) until
	// the named lease is held or ctx is cancelled.
	Acquire(ctx context.Context, name string) (Lease, error)
}

// Lease is one held leadership grant.
type Lease interface {
	// Done closes when leadership ends — loss or Release.
	Done() <-chan struct{}
	// Err reports why leadership ended: ErrLeaseLost when involuntary, nil
	// after a voluntary Release or while still held.
	Err() error
	// Release voluntarily gives up leadership (idempotent).
	Release(ctx context.Context) error
}

// Config tunes lease timing. The TTL bounds failover: a dead holder's lease
// becomes acquirable once expires_at passes.
type Config struct {
	// Holder identifies this replica (observability; must differ across
	// replicas and restarts). Defaults to hostname + random suffix.
	Holder string
	// TTL is how long a lease stays valid without renewal. Default 10s.
	TTL time.Duration
	// RenewInterval is how often a held lease is renewed. Default TTL/3.
	RenewInterval time.Duration
	// AcquireRetry is the pause between acquisition attempts. Default 1s.
	AcquireRetry time.Duration
}

func (c Config) withDefaults() Config {
	if c.Holder == "" {
		host, err := os.Hostname()
		if err != nil || host == "" {
			host = "inari-server"
		}
		c.Holder = host + "-" + uuid.NewString()[:8]
	}
	if c.TTL <= 0 {
		c.TTL = 10 * time.Second
	}
	if c.RenewInterval <= 0 {
		c.RenewInterval = c.TTL / 3
	}
	if c.AcquireRetry <= 0 {
		c.AcquireRetry = time.Second
	}
	return c
}

// store is the row-level seam (pgStore in production, fakes in tests) so the
// renewal state machine is unit-testable without a database.
type store interface {
	// acquire takes the lease if free or expired; reports whether held.
	acquire(ctx context.Context, name, holder string, ttl time.Duration) (bool, error)
	// renew extends the lease; false means another holder owns the row.
	renew(ctx context.Context, name, holder string, ttl time.Duration) (bool, error)
	release(ctx context.Context, name, holder string) error
}

type leaser struct {
	s   store
	cfg Config
}

// New returns a Postgres-backed Leaser.
func New(d *db.DB, cfg Config) Leaser {
	return NewWithStore(&pgStore{pool: d.Pool}, cfg)
}

// NewWithStore is the test seam.
func NewWithStore(s store, cfg Config) Leaser {
	return &leaser{s: s, cfg: cfg.withDefaults()}
}

// Acquire implements Leaser.
func (l *leaser) Acquire(ctx context.Context, name string) (Lease, error) {
	for {
		ok, err := l.s.acquire(ctx, name, l.cfg.Holder, l.cfg.TTL)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			slog.Warn("leaderlease: acquire failed, retrying", "lease", name, "error", err)
		} else if ok {
			return l.newLease(ctx, name), nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(l.cfg.AcquireRetry):
		}
	}
}

// lease is a held grant with a background renewal goroutine.
type lease struct {
	s      store
	name   string
	holder string
	ttl    time.Duration

	done   chan struct{}
	stop   chan struct{}
	stopMu sync.Once
	mu     sync.Mutex
	err    error
}

func (l *leaser) newLease(ctx context.Context, name string) *lease {
	ls := &lease{
		s: l.s, name: name, holder: l.cfg.Holder, ttl: l.cfg.TTL,
		done: make(chan struct{}), stop: make(chan struct{}),
	}
	go ls.renewLoop(ctx, l.cfg.RenewInterval)
	return ls
}

func (ls *lease) Done() <-chan struct{} { return ls.done }

func (ls *lease) Err() error {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return ls.err
}

// renewLoop extends the lease until Release, loss, or parent cancellation.
// A definitive renew miss (another holder) forfeits immediately; transient
// errors only forfeit once no successful renewal has happened within the
// TTL — by then another replica may legitimately have taken over.
func (ls *lease) renewLoop(ctx context.Context, interval time.Duration) {
	defer close(ls.done)
	lastOK := time.Now()
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ls.stop:
			return
		case <-ctx.Done():
			// Parent shutdown is not leadership loss.
			return
		case <-tick.C:
			ok, err := ls.s.renew(ctx, ls.name, ls.holder, ls.ttl)
			switch {
			case err != nil && ctx.Err() != nil:
				return
			case err != nil:
				slog.Warn("leaderlease: renew failed", "lease", ls.name, "error", err)
				if time.Since(lastOK) > ls.ttl {
					ls.forfeit()
					return
				}
			case !ok:
				ls.forfeit()
				return
			default:
				lastOK = time.Now()
			}
		}
	}
}

func (ls *lease) forfeit() {
	ls.mu.Lock()
	if ls.err == nil {
		ls.err = ErrLeaseLost
	}
	ls.mu.Unlock()
	slog.Warn("leaderlease: leadership lost", "lease", ls.name)
}

func (ls *lease) Release(ctx context.Context) error {
	ls.stopMu.Do(func() { close(ls.stop) })
	<-ls.done
	if err := ls.s.release(ctx, ls.name, ls.holder); err != nil {
		return fmt.Errorf("leaderlease: release %s: %w", ls.name, err)
	}
	return nil
}

// Run gates fn on the named lease: acquire, run fn with a context cancelled
// on lease loss, release, then re-acquire. Non-leaders idle in Acquire. Run
// returns when ctx is cancelled.
func Run(ctx context.Context, l Leaser, name string, fn func(ctx context.Context), log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}
	for {
		lease, err := l.Acquire(ctx, name)
		if err != nil {
			return // parent ctx cancelled
		}
		log.Info("leaderlease: acquired", "lease", name)
		lctx, cancel := context.WithCancel(ctx)
		go func() {
			select {
			case <-lease.Done():
				cancel()
			case <-lctx.Done():
			}
		}()
		fn(lctx)
		cancel()
		if err := lease.Err(); err != nil {
			log.Warn("leaderlease: loop stopped on lease loss", "lease", name, "error", err)
		}
		relCtx, relCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := lease.Release(relCtx); err != nil {
			log.Warn("leaderlease: release failed", "lease", name, "error", err)
		}
		relCancel()
		// Back off before re-acquiring so a fast-returning fn cannot hot-loop.
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}
