package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis is the shared backend (INARI_CACHE_BACKEND=redis,
// INARI_REDIS_URL=redis://host:6379/0). Timeouts are deliberately short:
// every caller fails open to the upstream call, so a slow Redis must never
// stall the request path.
type Redis struct {
	client *redis.Client
}

// NewRedis parses url (redis://[user:pass@]host:port/db) and verifies
// connectivity. A connection error at startup is a hard error (operator
// opted into redis); runtime errors after that are fail-open at call sites.
func NewRedis(url string) (*Redis, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("cache: redis url: %w", err)
	}
	opts.DialTimeout = 2 * time.Second
	opts.ReadTimeout = time.Second
	opts.WriteTimeout = time.Second
	// Fail fast: every caller degrades to the upstream call on error, so
	// go-redis retries (with backoff) would only add outage latency on the
	// request path.
	opts.MaxRetries = -1
	r := &Redis{client: redis.NewClient(opts)}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.client.Ping(ctx).Err(); err != nil {
		_ = r.client.Close()
		return nil, fmt.Errorf("cache: redis ping: %w", err)
	}
	return r, nil
}

func (r *Redis) Get(ctx context.Context, key string) (string, bool, error) {
	v, err := r.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("cache: redis get: %w", err)
	}
	return v, true, nil
}

func (r *Redis) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	if err := r.client.Set(ctx, key, value, ttl).Err(); err != nil {
		return fmt.Errorf("cache: redis set: %w", err)
	}
	return nil
}

func (r *Redis) Delete(ctx context.Context, key string) error {
	if err := r.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("cache: redis delete: %w", err)
	}
	return nil
}

func (r *Redis) Increment(ctx context.Context, key string) (int64, error) {
	n, err := r.client.Incr(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("cache: redis incr: %w", err)
	}
	return n, nil
}

func (r *Redis) Close(context.Context) error {
	return r.client.Close()
}
