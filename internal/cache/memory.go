package cache

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// DefaultMemoryMaxEntries bounds the in-process cache when
// INARI_CACHE_MEMORY_MAX_ENTRIES is unset.
const DefaultMemoryMaxEntries = 10000

type memoryEntry struct {
	value   string
	expires time.Time // zero = never
}

// Memory is the default in-process backend: a mutex-guarded map with
// per-entry TTL (lazy expiry on read) and a max-entries bound. Multi-replica
// note: entries are process-local, so cross-replica consistency relies on
// TTL; use the redis backend for shared invalidation.
type Memory struct {
	mu      sync.Mutex
	entries map[string]memoryEntry
	max     int
	now     func() time.Time
}

// NewMemory returns an in-process Cache holding at most maxEntries entries
// (DefaultMemoryMaxEntries when <= 0). When full, Set evicts expired entries
// first, then arbitrary ones.
func NewMemory(maxEntries int) *Memory {
	if maxEntries <= 0 {
		maxEntries = DefaultMemoryMaxEntries
	}
	return &Memory{entries: make(map[string]memoryEntry), max: maxEntries, now: time.Now}
}

// Len reports the number of live (unexpired) entries. Test/diagnostic use.
func (m *Memory) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweepLocked()
	return len(m.entries)
}

func (m *Memory) Get(_ context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	if !ok {
		return "", false, nil
	}
	if m.expired(e) {
		delete(m.entries, key)
		return "", false, nil
	}
	return e.value, true, nil
}

func (m *Memory) Set(_ context.Context, key, value string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.entries[key]; !ok && len(m.entries) >= m.max {
		m.sweepLocked()
		for len(m.entries) >= m.max {
			// Map iteration order is random: evict one arbitrary entry.
			for k := range m.entries {
				delete(m.entries, k)
				break
			}
		}
	}
	e := memoryEntry{value: value}
	if ttl > 0 {
		e.expires = m.now().Add(ttl)
	}
	m.entries[key] = e
	return nil
}

func (m *Memory) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, key)
	return nil
}

func (m *Memory) Increment(_ context.Context, key string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	if e, ok := m.entries[key]; ok && !m.expired(e) {
		v, err := strconv.ParseInt(e.value, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("cache: increment non-integer key %q: %w", key, err)
		}
		n = v
	}
	n++
	m.entries[key] = memoryEntry{value: strconv.FormatInt(n, 10)} // no TTL
	return n, nil
}

// Close is a no-op for the in-process backend.
func (m *Memory) Close(context.Context) error { return nil }

func (m *Memory) expired(e memoryEntry) bool {
	return !e.expires.IsZero() && m.now().After(e.expires)
}

func (m *Memory) sweepLocked() {
	for k, e := range m.entries {
		if m.expired(e) {
			delete(m.entries, k)
		}
	}
}
