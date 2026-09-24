package server

import (
	"sync"
	"time"
)

// RateLimiter is a small in-memory sliding-window limiter (per-key counts).
// It guards join attempts, message sends, and wake-up registration
// (429 throttled + Retry-After per the spec).
type RateLimiter struct {
	mu      sync.Mutex
	windows map[string]*window
	now     func() time.Time
}

type window struct {
	start time.Time
	count int
}

// NewRateLimiter builds the limiter.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{windows: map[string]*window{}, now: time.Now}
}

// Allow reports whether one more hit is allowed for key within maxCount
// per window duration. It records the hit when allowed.
func (l *RateLimiter) Allow(key string, maxCount int, windowLen time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.windows[key]
	now := l.now()
	if !ok || now.Sub(w.start) >= windowLen {
		l.windows[key] = &window{start: now, count: 1}
		return true
	}
	if w.count >= maxCount {
		return false
	}
	w.count++
	return true
}

// Failures tracks consecutive failures for the join throttle (E1): after
// max consecutive wrong-password attempts the join is refused with 429 +
// Retry-After instead of 403.
type FailureTracker struct {
	mu       sync.Mutex
	failures map[string]int
	now      func() time.Time
	last     map[string]time.Time
}

// NewFailureTracker builds the tracker.
func NewFailureTracker() *FailureTracker {
	return &FailureTracker{
		failures: map[string]int{},
		last:     map[string]time.Time{},
		now:      time.Now,
	}
}

const joinFailureWindow = 10 * time.Minute

// Blocked reports whether the key is currently throttled by failures and
// how many seconds remain.
func (f *FailureTracker) Blocked(key string, max int) (bool, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failures[key] < max {
		return false, 0
	}
	remaining := joinFailureWindow - f.now().Sub(f.last[key])
	if remaining <= 0 {
		delete(f.failures, key)
		return false, 0
	}
	return true, int(remaining.Seconds()) + 1
}

// RecordFailure adds one wrong-password attempt for the key.
func (f *FailureTracker) RecordFailure(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures[key]++
	f.last[key] = f.now()
}

// Reset clears the failure history for the key (successful join).
func (f *FailureTracker) Reset(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.failures, key)
	delete(f.last, key)
}
