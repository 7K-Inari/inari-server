// Package cache provides a small key-value cache with TTL behind a strict
// internal interface, with two backends selected by INARI_CACHE_BACKEND:
// memory (default, in-process) and redis (INARI_REDIS_URL). Used by the
// OpenFGA PEP cache (internal/authz) and the tenant-slug cache
// (internal/tenancy). Callers must treat every error as fail-open: a cache
// outage degrades to a direct upstream call, never a failed request.
package cache

import (
	"context"
	"fmt"
	"time"
)

// Backend names for Config.Backend / INARI_CACHE_BACKEND.
const (
	BackendMemory = "memory"
	BackendRedis  = "redis"
)

// Cache is the module-facing cache contract. Values are strings (callers
// encode); TTL applies to Set only — Increment keys never expire (they are
// generation counters).
type Cache interface {
	// Get returns the value and whether it was present (and unexpired).
	Get(ctx context.Context, key string) (string, bool, error)
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	// Delete removes a key; deleting a missing key is not an error.
	Delete(ctx context.Context, key string) error
	// Increment atomically adds 1 and returns the new value. Creates the
	// key at 1 if absent. Errors if the existing value is not an integer.
	Increment(ctx context.Context, key string) (int64, error)
	Close(ctx context.Context) error
}

// Config selects and parameterizes a backend.
type Config struct {
	Backend          string
	RedisURL         string
	MemoryMaxEntries int
}

// New builds the configured backend. An unknown backend is a config error.
func New(cfg Config) (Cache, error) {
	switch cfg.Backend {
	case "", BackendMemory:
		return NewMemory(cfg.MemoryMaxEntries), nil
	case BackendRedis:
		return NewRedis(cfg.RedisURL)
	}
	return nil, fmt.Errorf("cache: unknown backend %q (want %q or %q)", cfg.Backend, BackendMemory, BackendRedis)
}
