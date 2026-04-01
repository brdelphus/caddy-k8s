package k8singress

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/redis/go-redis/v9"
)

// routeStore persists the Ingress key → owned Caddy route IDs mapping.
//
// The default implementation is in-memory. When Redis is configured, it acts
// as a write-through layer: every mutation is stored in Redis so the mapping
// survives Caddy restarts. On startup, the module restores the map from Redis
// and can properly clean up routes belonging to Ingresses that were deleted
// while Caddy was down.
type routeStore interface {
	// save stores the route IDs owned by an Ingress ("namespace/name").
	save(ctx context.Context, key string, ids []string) error
	// remove deletes the entry for an Ingress.
	remove(ctx context.Context, key string) error
	// loadAll returns the full map, used during startup to restore state.
	loadAll(ctx context.Context) (map[string][]string, error)
	// close releases any underlying connections.
	close() error
}

// ── In-memory store (default) ─────────────────────────────────────────────

type memoryStore struct {
	mu   sync.RWMutex
	data map[string][]string
}

func newMemoryStore() *memoryStore {
	return &memoryStore{data: make(map[string][]string)}
}

func (s *memoryStore) save(_ context.Context, key string, ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = ids
	return nil
}

func (s *memoryStore) remove(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

func (s *memoryStore) loadAll(_ context.Context) (map[string][]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string][]string, len(s.data))
	for k, v := range s.data {
		cp := make([]string, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out, nil
}

func (s *memoryStore) close() error { return nil }

// ── Redis store ───────────────────────────────────────────────────────────

// RedisConfig holds the connection parameters for the optional Redis backend.
type RedisConfig struct {
	// Address is the Redis server address (host:port).
	// Example: redis.redis.svc.cluster.local:6379
	Address string `json:"address"`

	// Password is optional. Leave empty if Redis has no auth.
	Password string `json:"password,omitempty"`

	// DB is the Redis database index (default 0).
	DB int `json:"db,omitempty"`
}

type redisStore struct {
	client    *redis.Client
	keyPrefix string // e.g. "k8s_ingress:caddy:"
}

func newRedisStore(cfg *RedisConfig, ingressClass string) (*redisStore, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Address,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("redis ping %s: %w", cfg.Address, err)
	}
	return &redisStore{
		client:    client,
		keyPrefix: fmt.Sprintf("k8s_ingress:%s:", ingressClass),
	}, nil
}

func (s *redisStore) save(ctx context.Context, key string, ids []string) error {
	b, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, s.keyPrefix+key, b, 0).Err()
}

func (s *redisStore) remove(ctx context.Context, key string) error {
	return s.client.Del(ctx, s.keyPrefix+key).Err()
}

func (s *redisStore) loadAll(ctx context.Context) (map[string][]string, error) {
	pattern := s.keyPrefix + "*"
	keys, err := s.client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("redis keys %s: %w", pattern, err)
	}
	out := make(map[string][]string, len(keys))
	prefixLen := len(s.keyPrefix)
	for _, k := range keys {
		val, err := s.client.Get(ctx, k).Result()
		if err != nil {
			continue
		}
		var ids []string
		if err := json.Unmarshal([]byte(val), &ids); err != nil {
			continue
		}
		out[k[prefixLen:]] = ids
	}
	return out, nil
}

func (s *redisStore) close() error {
	return s.client.Close()
}
