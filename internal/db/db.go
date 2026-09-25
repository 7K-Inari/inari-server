// Package db provides the pgx pool, goose migrations, and the transactor
// that lets module stores run atomically with their outbox writes.
package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Querier is satisfied by *pgxpool.Pool and pgx.Tx so stores accept either.
type Querier interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type DB struct {
	Pool *pgxpool.Pool
}

func Connect(ctx context.Context, url string) (*DB, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("db: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}
	return &DB{Pool: pool}, nil
}

func (d *DB) Close() { d.Pool.Close() }

func (d *DB) Ping(ctx context.Context) error { return d.Pool.Ping(ctx) }

// DefaultLockWaitTimeout bounds how long Migrate waits for the cross-replica
// migration lock before failing fast (ADR 0010).
const DefaultLockWaitTimeout = 60 * time.Second

// lockProbePeriod is how often the goose session locker retries
// pg_try_advisory_lock; the wait bound is rounded up to whole probes.
const lockProbePeriod = 5 * time.Second

// MigrateOption customizes Migrate behavior.
type MigrateOption func(*migrateConfig)

type migrateConfig struct {
	lockWaitTimeout time.Duration
}

// WithLockWaitTimeout bounds how long Migrate waits to acquire the
// cross-replica migration advisory lock before failing. Mainly for tests;
// production uses DefaultLockWaitTimeout.
func WithLockWaitTimeout(d time.Duration) MigrateOption {
	return func(c *migrateConfig) { c.lockWaitTimeout = d }
}

// loggingSessionLocker wraps the goose session locker with structured logging
// and a fail-fast error that names the lock and the bounded wait.
type loggingSessionLocker struct {
	inner   lock.SessionLocker
	maxWait time.Duration
}

func (l loggingSessionLocker) SessionLock(ctx context.Context, conn *sql.Conn) error {
	slog.Info("db: acquiring migration lock", "lock_id", lock.DefaultLockID, "max_wait", l.maxWait)
	start := time.Now()
	if err := l.inner.SessionLock(ctx, conn); err != nil {
		return fmt.Errorf("migration lock not acquired within %s: %w", l.maxWait, err)
	}
	slog.Info("db: migration lock acquired", "lock_id", lock.DefaultLockID, "waited", time.Since(start).Round(time.Millisecond))
	return nil
}

func (l loggingSessionLocker) SessionUnlock(ctx context.Context, conn *sql.Conn) error {
	return l.inner.SessionUnlock(ctx, conn)
}

// Migrate applies all pending goose migrations, serialized across replicas by
// a PostgreSQL session-level advisory lock (ADR 0010): concurrent first boots
// wait for the lock holder to finish instead of racing DDL. A replica that
// cannot acquire the lock within the bounded wait fails fast.
func (d *DB) Migrate(ctx context.Context, opts ...MigrateOption) error {
	cfg := migrateConfig{lockWaitTimeout: DefaultLockWaitTimeout}
	for _, opt := range opts {
		opt(&cfg)
	}
	threshold := max(1, uint64((cfg.lockWaitTimeout+lockProbePeriod-1)/lockProbePeriod))
	locker, err := lock.NewPostgresSessionLocker(
		lock.WithLockTimeout(uint64(lockProbePeriod/time.Second), threshold),
	)
	if err != nil {
		return fmt.Errorf("db: migration locker: %w", err)
	}
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("db: migrations fs: %w", err)
	}
	sqlDB := stdlib.OpenDBFromPool(d.Pool)
	defer func() { _ = sqlDB.Close() }()
	provider, err := goose.NewProvider(
		goose.DialectPostgres,
		sqlDB,
		sub,
		goose.WithSessionLocker(loggingSessionLocker{inner: locker, maxWait: time.Duration(threshold) * lockProbePeriod}),
		goose.WithSlog(slog.Default()),
	)
	if err != nil {
		return fmt.Errorf("db: goose provider: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("db: migrate: %w", err)
	}
	return nil
}

// WithTx runs fn inside a transaction; commits on nil error, rolls back otherwise.
func (d *DB) WithTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := d.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("db: begin tx: %w", err)
	}
	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(ctx); rbErr != nil && !errors.Is(rbErr, pgx.ErrTxClosed) {
			return fmt.Errorf("db: tx: %w (rollback: %v)", err, rbErr)
		}
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("db: commit: %w", err)
	}
	return nil
}
