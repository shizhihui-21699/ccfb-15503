// Package ratelimit implements a per-tenant token bucket.
//
// The bucket is the cheap first line of defence: it stops an attacker from
// flooding the API to harvest independent noise draws and average them away.
// Cached-snapshot hits count toward the limit so the bucket also bounds how
// often an attacker can probe response timing; the privacy ledger (dp.Ledger)
// is the second, budget-based line.
package ratelimit

import "sync"

// Bucket is a standard token bucket with lazy refill.
type Bucket struct {
	mu sync.Mutex

	rate    float64 // tokens added per second
	burst   float64 // maximum tokens
	tokens  float64
	lastSec float64 // unix seconds (float to keep tests wall-clock free)
}

// New creates a bucket refilling rate tokens/second up to burst capacity.
func New(ratePerSec float64, burst int) *Bucket {
	return &Bucket{
		rate:    ratePerSec,
		burst:   float64(burst),
		tokens:  float64(burst),
		lastSec: 0,
	}
}

// Allow consumes one token if available. nowSec is unix time in seconds and
// is injected (rather than read internally) so tests are deterministic.
func (b *Bucket) Allow(nowSec float64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.lastSec == 0 {
		b.lastSec = nowSec
	}
	elapsed := nowSec - b.lastSec
	if elapsed > 0 {
		b.tokens += elapsed * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.lastSec = nowSec
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}
