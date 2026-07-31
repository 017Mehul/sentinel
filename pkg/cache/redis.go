package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/MehulChamoli/auth-service/config"
)

// Client wraps the Redis client with typed helpers.
// All methods accept a context for deadline/cancellation propagation.
type Client struct {
	rdb *redis.Client
}

// NewRedisClient creates and validates a Redis connection.
func NewRedisClient(cfg *config.RedisConfig) (*Client, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:         cfg.Addr,
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("connecting to Redis: %w", err)
	}

	return &Client{rdb: rdb}, nil
}

// Raw returns the underlying *redis.Client for advanced use cases.
func (c *Client) Raw() *redis.Client {
	return c.rdb
}

// Set stores a string value with an optional TTL. TTL=0 means no expiry.
func (c *Client) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return c.rdb.Set(ctx, key, value, ttl).Err()
}

// SetNX stores a value only if the key does not exist (atomic).
// Returns true if the key was set, false if it already existed.
func (c *Client) SetNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error) {
	return c.rdb.SetNX(ctx, key, value, ttl).Result()
}

// Get retrieves a string value. Returns ("", ErrNotFound) if key is absent.
func (c *Client) Get(ctx context.Context, key string) (string, error) {
	val, err := c.rdb.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrNotFound
	}
	return val, err
}

// SetJSON serialises v as JSON and stores it with an optional TTL.
func (c *Client) SetJSON(ctx context.Context, key string, v any, ttl time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshalling JSON for key %q: %w", key, err)
	}
	return c.rdb.Set(ctx, key, b, ttl).Err()
}

// GetJSON retrieves a JSON-encoded value and deserialises it into dst.
func (c *Client) GetJSON(ctx context.Context, key string, dst any) error {
	b, err := c.rdb.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

// Delete removes one or more keys.
func (c *Client) Delete(ctx context.Context, keys ...string) error {
	return c.rdb.Del(ctx, keys...).Err()
}

// Exists returns true if all given keys exist.
func (c *Client) Exists(ctx context.Context, keys ...string) (bool, error) {
	n, err := c.rdb.Exists(ctx, keys...).Result()
	return n == int64(len(keys)), err
}

// Expire updates the TTL of an existing key.
func (c *Client) Expire(ctx context.Context, key string, ttl time.Duration) error {
	return c.rdb.Expire(ctx, key, ttl).Err()
}

// Incr atomically increments a counter and returns the new value.
func (c *Client) Incr(ctx context.Context, key string) (int64, error) {
	return c.rdb.Incr(ctx, key).Result()
}

// incrWithExpireScript atomically increments a counter and sets the TTL only
// when the key is first created. This implements a true fixed-window counter:
// the window starts when the first request arrives and expires after `ttl`.
// Calling EXPIRE on every increment (as a pipeline does) would reset the window
// on every request, allowing an attacker to prevent the key from ever expiring.
var incrWithExpireScript = redis.NewScript(`
local current = redis.call("INCR", KEYS[1])
if current == 1 then
    redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
return current
`)

// IncrWithExpire atomically increments and sets TTL only when the key is new (count == 1).
func (c *Client) IncrWithExpire(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	result, err := incrWithExpireScript.Run(ctx, c.rdb, []string{key}, ttl.Milliseconds()).Int64()
	if err != nil {
		return 0, err
	}
	return result, nil
}

// DeletePattern removes all keys matching a glob pattern.
// Use carefully — SCAN is used (not KEYS) to avoid blocking.
func (c *Client) DeletePattern(ctx context.Context, pattern string) error {
	var cursor uint64
	for {
		keys, next, err := c.rdb.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return err
		}
		if len(keys) > 0 {
			if err := c.rdb.Del(ctx, keys...).Err(); err != nil {
				return err
			}
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return nil
}

// Ping checks Redis connectivity.
func (c *Client) Ping(ctx context.Context) error {
	return c.rdb.Ping(ctx).Err()
}

// Close closes the Redis connection pool.
func (c *Client) Close() error {
	return c.rdb.Close()
}

// ErrNotFound is returned when a key does not exist in Redis.
var ErrNotFound = errors.New("redis: key not found")
