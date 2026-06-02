package main

import (
	"net"
	"sync"
	"time"
)

// maxRateBuckets bounds the rate-limiter map so a flood of distinct source
// keys cannot exhaust memory between sweeps. When the cap is hit, new keys are
// allowed without tracking (the global concurrency semaphore still applies).
const maxRateBuckets = 1 << 20

// rateLimiter caps how frequently a single source IP can have connections
// processed. This bounds connection-flood load and the velocity of unbounded
// fingerprint-row growth from randomized KEXINIT packets.
type rateLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*tokenBucket
	rate       float64
	burst      float64
	ttl        time.Duration
	maxBuckets int
	now        func() time.Time
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(rate, burst float64, ttl time.Duration) *rateLimiter {
	return &rateLimiter{
		buckets:    make(map[string]*tokenBucket),
		rate:       rate,
		burst:      burst,
		ttl:        ttl,
		maxBuckets: maxRateBuckets,
		now:        time.Now,
	}
}

// rateLimitKey normalizes a source IP into a bucket key. IPv6 addresses are
// masked to their /64 so a client with a routed prefix cannot bypass the limit
// (or balloon the bucket map) by rotating through addresses it controls.
func rateLimitKey(ip string) string {
	addr := net.ParseIP(ip)
	if addr == nil {
		return ip
	}
	if addr.To4() != nil {
		return ip
	}
	return addr.Mask(net.CIDRMask(64, 128)).String()
}

func (rl *rateLimiter) allow(key string) bool {
	if rl == nil {
		return true
	}
	key = rateLimitKey(key)
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	b := rl.buckets[key]
	if b == nil {
		if rl.maxBuckets > 0 && len(rl.buckets) >= rl.maxBuckets {
			// Map full: allow without tracking to bound memory.
			return true
		}
		b = &tokenBucket{tokens: rl.burst, last: now}
		rl.buckets[key] = b
	} else {
		b.tokens += now.Sub(b.last).Seconds() * rl.rate
		if b.tokens > rl.burst {
			b.tokens = rl.burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (rl *rateLimiter) sweep() {
	if rl == nil {
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := rl.now().Add(-rl.ttl)
	for k, b := range rl.buckets {
		if b.last.Before(cutoff) {
			delete(rl.buckets, k)
		}
	}
}

func (rl *rateLimiter) runSweeper(interval time.Duration) {
	if rl == nil {
		return
	}
	for range time.Tick(interval) {
		rl.sweep()
	}
}
