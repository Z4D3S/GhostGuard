package detector

import (
	"sync"
	"time"
)

type RateLimiter struct {
	mu       sync.Mutex
	windows  map[string]*rateBucket
	limit    int
	interval time.Duration
}

type rateBucket struct {
	count    int
	resetAt  time.Time
}

func NewRateLimiter(limit int, interval time.Duration) *RateLimiter {
	rl := &RateLimiter{
		windows:  make(map[string]*rateBucket),
		limit:    limit,
		interval: interval,
	}
	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	bucket, exists := rl.windows[key]

	if !exists || now.After(bucket.resetAt) {
		rl.windows[key] = &rateBucket{
			count:   1,
			resetAt: now.Add(rl.interval),
		}
		return true
	}

	if bucket.count >= rl.limit {
		return false
	}

	bucket.count++
	return true
}

func (rl *RateLimiter) Remaining(key string) int {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	bucket, exists := rl.windows[key]
	if !exists {
		return rl.limit
	}

	remaining := rl.limit - bucket.count
	if remaining < 0 {
		return 0
	}
	return remaining
}

func (rl *RateLimiter) Reset(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.windows, key)
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.interval)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for k, bucket := range rl.windows {
			if now.After(bucket.resetAt) {
				delete(rl.windows, k)
			}
		}
		rl.mu.Unlock()
	}
}
