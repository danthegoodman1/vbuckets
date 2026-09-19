package controlplane

import (
	"container/list"
	"context"
	"math"
	"sync"
	"time"

	"github.com/danthegoodman1/vbuckets/env"
	"github.com/danthegoodman1/vbuckets/http_server"
)

type cachedCredentials struct {
	*http_server.VirtualCredentials
	Found    bool
	Revision uint64
	TTL      time.Duration
}

type cachedVBucket struct {
	*http_server.VBucketConfig
	Found    bool
	Revision uint64
	TTL      time.Duration
}

type timedEntry[V any] struct {
	value     V
	expiresAt time.Time
	order     *list.Element
}

// localCache is intentionally small: revision arbitration is owned by Client's
// synchronization lock, while this type owns bounded storage and TTL expiry.
// It does not run loaders, which avoids the classic loader-completion race in
// which a stale unary response overwrites a newer watch event.
type localCache[K comparable, V any] struct {
	mu      sync.Mutex
	entries map[K]timedEntry[V]
	order   *list.List
	maximum int
	onEvict func()
	now     func() time.Time
}

func newLocalCache[K comparable, V any](maximum int, onEvict func(), now func() time.Time) *localCache[K, V] {
	if maximum < 1 {
		maximum = 1
	}
	return &localCache[K, V]{entries: make(map[K]timedEntry[V]), order: list.New(), maximum: maximum, onEvict: onEvict, now: now}
}

func (c *localCache[K, V]) GetIfPresent(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		var zero V
		return zero, false
	}
	if !entry.expiresAt.After(c.now()) {
		c.order.Remove(entry.order)
		delete(c.entries, key)
		var zero V
		return zero, false
	}
	c.order.MoveToFront(entry.order)
	return entry.value, true
}

func (c *localCache[K, V]) Set(key K, value V, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.entries[key]; ok {
		existing.value = value
		existing.expiresAt = c.now().Add(ttl)
		c.order.MoveToFront(existing.order)
		c.entries[key] = existing
		return
	}
	order := c.order.PushFront(key)
	c.entries[key] = timedEntry[V]{value: value, expiresAt: c.now().Add(ttl), order: order}
	if len(c.entries) <= c.maximum {
		return
	}
	oldest := c.order.Back()
	oldestKey := oldest.Value.(K)
	c.order.Remove(oldest)
	delete(c.entries, oldestKey)
	if c.onEvict != nil {
		c.onEvict()
	}
}

func (c *localCache[K, V]) Invalidate(key K) {
	c.mu.Lock()
	if entry, ok := c.entries[key]; ok {
		c.order.Remove(entry.order)
	}
	delete(c.entries, key)
	c.mu.Unlock()
}

func (c *localCache[K, V]) InvalidateAll() {
	c.mu.Lock()
	c.entries = make(map[K]timedEntry[V])
	c.order.Init()
	c.mu.Unlock()
}

func (c *localCache[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

type caches struct {
	credentials *localCache[string, cachedCredentials]
	vbuckets    *localCache[string, cachedVBucket]
}

func newCaches(onEvict func(), now func() time.Time) *caches {
	return &caches{
		credentials: newLocalCache[string, cachedCredentials](env.Current.Cache.MaxCredentials, onEvict, now),
		vbuckets:    newLocalCache[string, cachedVBucket](env.Current.Cache.MaxVBuckets, onEvict, now),
	}
}

func vbucketCacheKey(accessKeyID, bucketName string) string {
	return accessKeyID + "/" + bucketName
}

type loadCall[V any] struct {
	done  chan struct{}
	value V
	err   error
	// waiters is guarded by loadGroup.mu and makes shared-call ownership
	// explicit for diagnostics and deterministic concurrency tests.
	waiters int
}

type loadGroup[K comparable, V any] struct {
	mu                       sync.Mutex
	calls                    map[K]*loadCall[V]
	afterCompletionPublished func()
}

func (g *loadGroup[K, V]) Do(ctx context.Context, key K, admit func() bool, load func() (V, error)) (V, error, bool) {
	g.mu.Lock()
	if g.calls == nil {
		g.calls = make(map[K]*loadCall[V])
	}
	if call, ok := g.calls[key]; ok {
		call.waiters++
		g.mu.Unlock()
		select {
		case <-call.done:
			return call.value, call.err, true
		case <-ctx.Done():
			var zero V
			return zero, ctx.Err(), true
		}
	}
	if admit != nil && !admit() {
		g.mu.Unlock()
		var zero V
		return zero, ErrMissRejected, false
	}
	call := &loadCall[V]{done: make(chan struct{})}
	g.calls[key] = call
	g.mu.Unlock()

	go func() {
		call.value, call.err = load()
		g.mu.Lock()
		if g.calls[key] == call {
			delete(g.calls, key)
		}
		g.mu.Unlock()
		// Completion means the call is no longer joinable. In particular, a
		// revision-race retry must create a fresh load instead of rejoining a
		// completed stale error.
		close(call.done)
		if g.afterCompletionPublished != nil {
			g.afterCompletionPublished()
		}
	}()
	select {
	case <-call.done:
		return call.value, call.err, false
	case <-ctx.Done():
		var zero V
		return zero, ctx.Err(), false
	}
}

type missAdmission struct {
	mu       sync.Mutex
	rate     float64
	burst    float64
	tokens   float64
	last     time.Time
	inflight chan struct{}
}

func newMissAdmission(rate float64, burst, inflight int, now time.Time) missAdmission {
	return missAdmission{rate: rate, burst: float64(burst), tokens: float64(burst), last: now, inflight: make(chan struct{}, inflight)}
}

func (a *missAdmission) acquire(now time.Time) bool {
	a.mu.Lock()
	elapsed := now.Sub(a.last).Seconds()
	a.last = now
	a.tokens = math.Min(a.burst, a.tokens+elapsed*a.rate)
	if a.tokens < 1 {
		a.mu.Unlock()
		return false
	}
	a.tokens--
	a.mu.Unlock()
	select {
	case a.inflight <- struct{}{}:
		return true
	default:
		return false
	}
}

func (a *missAdmission) release() { <-a.inflight }
