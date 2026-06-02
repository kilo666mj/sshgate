package main

import (
	"testing"
	"time"
)

func TestRateLimiterAllowAndRefill(t *testing.T) {
	now := time.Unix(0, 0)
	rl := newRateLimiter(1, 2, time.Minute)
	rl.now = func() time.Time { return now }

	if !rl.allow("ip") || !rl.allow("ip") {
		t.Fatal("initial burst should be allowed")
	}
	if rl.allow("ip") {
		t.Fatal("third request before refill should be denied")
	}
	now = now.Add(time.Second)
	if !rl.allow("ip") {
		t.Fatal("request after refill should be allowed")
	}
}

func TestRateLimitKeyMasksIPv6ToSlash64(t *testing.T) {
	a := rateLimitKey("2001:db8::1")
	b := rateLimitKey("2001:db8::dead:beef")
	if a != b {
		t.Fatalf("addresses in same /64 should share a key: %q != %q", a, b)
	}
	if c := rateLimitKey("2001:db9::1"); c == a {
		t.Fatalf("addresses in different /64 should not share a key: %q == %q", c, a)
	}
	if got := rateLimitKey("203.0.113.10"); got != "203.0.113.10" {
		t.Fatalf("IPv4 key = %q, want unchanged", got)
	}
}

func TestRateLimiterIPv6PrefixSharesBudget(t *testing.T) {
	now := time.Unix(0, 0)
	rl := newRateLimiter(1, 2, time.Minute)
	rl.now = func() time.Time { return now }

	if !rl.allow("2001:db8::1") || !rl.allow("2001:db8::2") {
		t.Fatal("first two from /64 should consume the shared burst")
	}
	if rl.allow("2001:db8::3") {
		t.Fatal("third from same /64 should be denied; rotation must not bypass the limit")
	}
}
