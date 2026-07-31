package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// ErrLockNotAcquired is returned when Acquire fails because another process
// holds the lock.
var ErrLockNotAcquired = errors.New("distributed lock: not acquired")

// Lock represents a held distributed lock. Call Unlock to release it.
type Lock struct {
	key   string
	token string // unique token prevents another process from releasing our lock
	rdb   *redis.Client
}

// Unlock releases the distributed lock.
// It uses a Lua script to atomically check the token before deleting,
// ensuring we only release locks we own.
func (l *Lock) Unlock(ctx context.Context) error {
	const script = `
		if redis.call("GET", KEYS[1]) == ARGV[1] then
			return redis.call("DEL", KEYS[1])
		else
			return 0
		end`
	err := redis.NewScript(script).Run(ctx, l.rdb, []string{l.key}, l.token).Err()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("releasing lock %q: %w", l.key, err)
	}
	return nil
}

// DistributedLock provides Redlock-style distributed locking backed by Redis.
// For single-node Redis (development + most production setups), this implementation
// is sufficient. True Redlock requires 5 independent Redis nodes.
type DistributedLock struct {
	rdb     *redis.Client
	retries int
	delay   time.Duration
}

// NewDistributedLock creates a DistributedLock using the given Redis client.
func NewDistributedLock(c *Client) *DistributedLock {
	return &DistributedLock{
		rdb:     c.rdb,
		retries: 3,
		delay:   50 * time.Millisecond,
	}
}

// Acquire attempts to acquire a distributed lock for the given key.
// It retries up to dl.retries times with dl.delay between attempts.
// Returns ErrLockNotAcquired if the lock cannot be obtained.
func (dl *DistributedLock) Acquire(ctx context.Context, key string, ttl time.Duration) (*Lock, error) {
	token := uuid.New().String()
	lockKey := "lock:" + key

	for attempt := 0; attempt <= dl.retries; attempt++ {
		ok, err := dl.rdb.SetNX(ctx, lockKey, token, ttl).Result()
		if err != nil {
			return nil, fmt.Errorf("acquiring lock %q: %w", lockKey, err)
		}
		if ok {
			return &Lock{key: lockKey, token: token, rdb: dl.rdb}, nil
		}

		if attempt < dl.retries {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(dl.delay):
			}
		}
	}

	return nil, fmt.Errorf("%w: %s", ErrLockNotAcquired, lockKey)
}

// WithLock is a convenience wrapper that acquires the lock, executes fn,
// and releases the lock automatically — even if fn panics.
func (dl *DistributedLock) WithLock(ctx context.Context, key string, ttl time.Duration, fn func() error) error {
	lock, err := dl.Acquire(ctx, key, ttl)
	if err != nil {
		return err
	}
	defer func() {
		// Best-effort unlock; lock will expire via TTL if this fails.
		_ = lock.Unlock(ctx)
	}()

	return fn()
}
