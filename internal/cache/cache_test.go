package cache

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestMemoryGetSetDelete(t *testing.T) {
	c := NewMemory(100)
	defer func() { _ = c.Close(context.Background()) }()
	ctx := context.Background()

	if _, ok, err := c.Get(ctx, "k"); err != nil || ok {
		t.Fatalf("Get(missing) = ok=%v err=%v, want ok=false err=nil", ok, err)
	}
	if err := c.Set(ctx, "k", "v", time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, ok, err := c.Get(ctx, "k")
	if err != nil || !ok || got != "v" {
		t.Fatalf("Get = %q,%v,%v, want v,true,nil", got, ok, err)
	}
	if err := c.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok, err := c.Get(ctx, "k"); err != nil || ok {
		t.Fatalf("Get(deleted) = ok=%v err=%v, want ok=false err=nil", ok, err)
	}
	// Delete of a missing key is a no-op.
	if err := c.Delete(ctx, "never-set"); err != nil {
		t.Fatalf("Delete(missing): %v", err)
	}
}

func TestMemoryTTLExpiry(t *testing.T) {
	c := NewMemory(100)
	defer func() { _ = c.Close(context.Background()) }()
	ctx := context.Background()

	if err := c.Set(ctx, "k", "v", 30*time.Millisecond); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, ok, _ := c.Get(ctx, "k"); !ok {
		t.Fatal("Get before expiry: want hit")
	}
	time.Sleep(60 * time.Millisecond)
	if _, ok, err := c.Get(ctx, "k"); err != nil || ok {
		t.Fatalf("Get after expiry = ok=%v err=%v, want ok=false err=nil", ok, err)
	}
}

func TestMemoryIncrement(t *testing.T) {
	c := NewMemory(100)
	defer func() { _ = c.Close(context.Background()) }()
	ctx := context.Background()

	n, err := c.Increment(ctx, "gen")
	if err != nil || n != 1 {
		t.Fatalf("Increment(new) = %d,%v, want 1,nil", n, err)
	}
	n, err = c.Increment(ctx, "gen")
	if err != nil || n != 2 {
		t.Fatalf("Increment = %d,%v, want 2,nil", n, err)
	}
	// Increment keys have no TTL: they persist.
	if err := c.Set(ctx, "plain", "x", time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := c.Increment(ctx, "plain"); err == nil {
		t.Fatal("Increment(non-numeric): want error")
	}
}

func TestMemoryMaxEntriesEviction(t *testing.T) {
	c := NewMemory(3)
	defer func() { _ = c.Close(context.Background()) }()
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		if err := c.Set(ctx, fmt.Sprintf("k%d", i), "v", time.Minute); err != nil {
			t.Fatalf("Set %d: %v", i, err)
		}
	}
	if n := c.Len(); n > 3 {
		t.Fatalf("Len = %d, want <= 3 after eviction", n)
	}
}

func TestMemoryConcurrent(t *testing.T) {
	c := NewMemory(1000)
	defer func() { _ = c.Close(context.Background()) }()
	ctx := context.Background()

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				key := fmt.Sprintf("g%d-k%d", g, i%10)
				if err := c.Set(ctx, key, "v", time.Minute); err != nil {
					t.Errorf("Set: %v", err)
				}
				if _, _, err := c.Get(ctx, key); err != nil {
					t.Errorf("Get: %v", err)
				}
				if _, err := c.Increment(ctx, "gen"); err != nil {
					t.Errorf("Increment: %v", err)
				}
				if err := c.Delete(ctx, key); err != nil {
					t.Errorf("Delete: %v", err)
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestNewFactory(t *testing.T) {
	c, err := New(Config{Backend: BackendMemory, MemoryMaxEntries: 10})
	if err != nil {
		t.Fatalf("New(memory): %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	if _, err := New(Config{Backend: "bogus"}); err == nil {
		t.Fatal("New(bogus): want error")
	}
	if _, err := New(Config{Backend: BackendRedis, RedisURL: "::bad-url::"}); err == nil {
		t.Fatal("New(redis, bad url): want error")
	}
}

// conformance exercises the Cache contract shared by all backends.
func conformance(t *testing.T, c Cache) {
	t.Helper()
	ctx := context.Background()

	if _, ok, err := c.Get(ctx, "missing"); err != nil || ok {
		t.Errorf("Get(missing) = ok=%v err=%v", ok, err)
	}
	if err := c.Set(ctx, "a", "1", time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, ok, err := c.Get(ctx, "a")
	if err != nil || !ok || got != "1" {
		t.Errorf("Get = %q,%v,%v, want 1,true,nil", got, ok, err)
	}
	if err := c.Delete(ctx, "a"); err != nil {
		t.Errorf("Delete: %v", err)
	}
	if _, ok, _ := c.Get(ctx, "a"); ok {
		t.Error("Get after Delete: want miss")
	}
	n, err := c.Increment(ctx, "gen")
	if err != nil || n != 1 {
		t.Errorf("Increment = %d,%v, want 1,nil", n, err)
	}
}

func TestMemoryConformance(t *testing.T) {
	c := NewMemory(100)
	defer func() { _ = c.Close(context.Background()) }()
	conformance(t, c)
}
