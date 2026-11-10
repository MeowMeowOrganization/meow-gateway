// Package ratelimit implements a bounded, instance-local admission limiter.
// Cross-replica enforcement belongs at a trusted ingress/shared backend.
package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	count int
	end   time.Time
}

type Limiter struct {
	mu         sync.Mutex
	limit      int
	window     time.Duration
	maxEntries int
	buckets    map[string]bucket
	now        func() time.Time
}

func New(limit int, window time.Duration, maxEntries int) *Limiter {
	if limit <= 0 || window <= 0 || maxEntries <= 0 {
		panic("ratelimit.New: nonpositive limit/window/maxEntries")
	}
	return &Limiter{limit: limit, window: window, maxEntries: maxEntries,
		buckets: make(map[string]bucket), now: time.Now}
}

// Allow returns whether a request may proceed and the retry delay on denial.
// It bounds the key cardinality, pruning stale entries when full. Capacity
// exhaustion fails closed instead of letting attackers allocate unbounded RAM.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	if key == "" {
		return false, l.window
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, found := l.buckets[key]
	if found && !now.Before(b.end) {
		delete(l.buckets, key)
		found = false
	}
	if !found {
		if len(l.buckets) >= l.maxEntries {
			for candidate, existing := range l.buckets {
				if !now.Before(existing.end) {
					delete(l.buckets, candidate)
				}
			}
		}
		if len(l.buckets) >= l.maxEntries {
			return false, l.window
		}
		b = bucket{end: now.Add(l.window)}
	}
	if b.count >= l.limit {
		return false, b.end.Sub(now)
	}
	b.count++
	l.buckets[key] = b
	return true, 0
}
