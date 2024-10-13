package verifier

import (
	"context"
	"time"

	"github.com/patrickmn/go-cache"
)

const (
	defaultCacheExpiration      = 5 * time.Minute
	defaultCacheCleanupInterval = 10 * time.Minute
)

// DefaultCache uses an in-memory key-value cache.
type DefaultCache struct {
	*cache.Cache
}

// NewDefaultCache creates a new DefaultCache.
func NewDefaultCache() DefaultCache {
	return DefaultCache{
		Cache: cache.New(defaultCacheExpiration, defaultCacheCleanupInterval),
	}
}

// Set adds an item to the cache, replacing any existing item. Uses the
// underlying Cache's default expiration.
func (d DefaultCache) Set(_ context.Context, key string, value any) {
	d.Cache.SetDefault(key, value)
}

// Get looks up an item in the cache, and returns true and the value if the
// item was found. It returns false otherwise. In all cases it returns a nil
// error.
func (d DefaultCache) Get(_ context.Context, key string) (any, bool) {
	return d.Cache.Get(key)
}

// NopCache is a no-op implementation of Cache.
type NopCache struct{}

// NewNopCache creates a new NopCache.
func NewNopCache() NopCache {
	return NopCache{}
}

// Set returns a nil error.
func (n NopCache) Set(context.Context, string, any) {}

// Get returns false and a nil error.
func (n NopCache) Get(context.Context, string) (any, bool) {
	return nil, false
}
