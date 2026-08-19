package detector

import (
	"sync"
	"testing"
	"time"
)

func TestRateLimiterAllow(t *testing.T) {
	rl := NewRateLimiter(3, time.Second)

	if !rl.Allow("host1") {
		t.Error("first call should be allowed")
	}
	if !rl.Allow("host1") {
		t.Error("second call should be allowed")
	}
	if !rl.Allow("host1") {
		t.Error("third call should be allowed")
	}
	if rl.Allow("host1") {
		t.Error("fourth call should be denied")
	}
}

func TestRateLimiterDifferentKeys(t *testing.T) {
	rl := NewRateLimiter(2, time.Second)

	rl.Allow("host1")
	rl.Allow("host1")

	if rl.Allow("host1") {
		t.Error("host1 should be limited")
	}

	if !rl.Allow("host2") {
		t.Error("host2 should still be allowed")
	}
}

func TestRateLimiterRemaining(t *testing.T) {
	rl := NewRateLimiter(5, time.Second)

	if rl.Remaining("host1") != 5 {
		t.Error("expected 5 remaining")
	}

	rl.Allow("host1")
	rl.Allow("host1")

	if rl.Remaining("host1") != 3 {
		t.Errorf("expected 3 remaining, got %d", rl.Remaining("host1"))
	}
}

func TestRateLimiterReset(t *testing.T) {
	rl := NewRateLimiter(2, time.Second)

	rl.Allow("host1")
	rl.Allow("host1")

	if rl.Allow("host1") {
		t.Error("should be limited")
	}

	rl.Reset("host1")

	if !rl.Allow("host1") {
		t.Error("should be allowed after reset")
	}
}

func TestRateLimiterConcurrent(t *testing.T) {
	rl := NewRateLimiter(100, time.Second)

	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rl.Allow("host1")
		}()
	}
	wg.Wait()

	if rl.Remaining("host1") != 0 {
		t.Errorf("expected 0 remaining, got %d", rl.Remaining("host1"))
	}
}
