// Package db provides the pgx pool, goose migrations, and the transactor
// that lets module stores run atomically with their outbox writes.
package db

import (
	"context"
	"embed"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
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

// Migrate applies all pending goose migrations.
func (d *DB) Migrate(ctx context.Context) error {
	goose.SetBaseFS(migrationsFS)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("db: goose dialect: %w", err)
	}
	sqlDB := stdlib.OpenDBFromPool(d.Pool)
	defer func() { _ = sqlDB.Close() }()
	if err := goose.UpContext(ctx, sqlDB, "migrations"); err != nil {
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
