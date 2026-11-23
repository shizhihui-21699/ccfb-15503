package ratelimit

import "testing"

func TestTokenBucket(t *testing.T) {
	b := New(10, 2) // 10 tokens/sec, burst 2

	// Burst capacity is available immediately.
	if !b.Allow(100.0) || !b.Allow(100.0) {
		t.Fatal("initial burst tokens should be granted")
	}
	if b.Allow(100.0) {
		t.Fatal("third immediate request must be denied")
	}

	// After 200 ms two tokens have refilled.
	if !b.Allow(100.2) {
		t.Fatal("first refilled token should be granted")
	}
	if !b.Allow(100.2) {
		t.Fatal("second refilled token should be granted")
	}
	if b.Allow(100.21) {
		t.Fatal("bucket must be empty again")
	}

	// Long idle restores the full burst cap (but never exceeds it).
	if !b.Allow(200.0) || !b.Allow(200.0) {
		t.Fatal("after long idle the full burst should be available")
	}
	if b.Allow(200.0) {
		t.Fatal("burst cap must not be exceeded")
	}
}

func TestTokenBucketMonotonic(t *testing.T) {
	b := New(1, 1)
	if !b.Allow(0) {
		t.Fatal("first request allowed")
	}
	// A same-instant retry cannot bypass the limit.
	if b.Allow(0) {
		t.Fatal("zero-interval retry must be denied")
	}
}
