package detector

import (
	"sync"
	"time"
)

type SlidingWindow struct {
	mu       sync.Mutex
	windows  map[string]*WindowBucket
	interval time.Duration
	maxAge   time.Duration
}

type WindowBucket struct {
	Count     int64
	FirstSeen time.Time
	LastSeen  time.Time
}

func NewSlidingWindow(interval, maxAge time.Duration) *SlidingWindow {
	sw := &SlidingWindow{
		windows:  make(map[string]*WindowBucket),
		interval: interval,
		maxAge:   maxAge,
	}
	go sw.cleanup()
	return sw
}

func (sw *SlidingWindow) Record(key string) int64 {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	now := time.Now()
	bucketKey := now.Truncate(sw.interval).Format(time.RFC3339)

	fullKey := key + ":" + bucketKey
	bucket, exists := sw.windows[fullKey]
	if !exists {
		bucket = &WindowBucket{
			FirstSeen: now,
		}
		sw.windows[fullKey] = bucket
	}

	bucket.Count++
	bucket.LastSeen = now
	return bucket.Count
}

func (sw *SlidingWindow) Count(key string) int64 {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	var total int64
	now := time.Now()
	cutoff := now.Add(-sw.maxAge)

	for fullKey, bucket := range sw.windows {
		if bucket.LastSeen.Before(cutoff) {
			continue
		}
		prefix := key + ":"
		if len(fullKey) > len(prefix) && fullKey[:len(prefix)] == prefix {
			total += bucket.Count
		}
	}
	return total
}

func (sw *SlidingWindow) cleanup() {
	ticker := time.NewTicker(sw.interval)
	defer ticker.Stop()

	for range ticker.C {
		sw.mu.Lock()
		cutoff := time.Now().Add(-sw.maxAge)
		for k, bucket := range sw.windows {
			if bucket.LastSeen.Before(cutoff) {
				delete(sw.windows, k)
			}
		}
		sw.mu.Unlock()
	}
}
