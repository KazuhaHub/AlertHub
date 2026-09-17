package api

import (
	"net/http"
	"strconv"
	"sync"
	"time"
)

// rateLimiter is a tiny fixed-window, per-key limiter used to slow credential
// brute-force on the auth endpoints. It is process-local (fits the single-binary
// tier); a clustered deployment would front it with a shared store. now is
// injectable for tests.
type rateLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	now    func() time.Time
	hits   map[string]*hitWindow
}

type hitWindow struct {
	count int
	reset time.Time
}

func newRateLimiter(max int, window time.Duration) *rateLimiter {
	return &rateLimiter{max: max, window: window, now: time.Now, hits: map[string]*hitWindow{}}
}

// allow records a hit for key and reports whether it is within the limit. It also
// drops windows that have expired, so the map stays bounded (no leak from a stream
// of distinct client IPs).
func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := rl.now()
	for k, w := range rl.hits {
		if now.After(w.reset) {
			delete(rl.hits, k)
		}
	}
	w, ok := rl.hits[key]
	if !ok || now.After(w.reset) {
		rl.hits[key] = &hitWindow{count: 1, reset: now.Add(rl.window)}
		return true
	}
	if w.count >= rl.max {
		return false
	}
	w.count++
	return true
}

// clientIP is the rate-limit key and the address recorded in the audit trail.
//
// X-Forwarded-For is believed only when the request arrived from a peer listed in
// ALERTHUB_TRUSTED_PROXIES; with none configured this is the TCP peer address,
// exactly as it was before that setting existed. See TrustedProxies for why
// getting this wrong breaks the limiter in both directions.
func (s *Server) clientIP(r *http.Request) string {
	return s.TrustedProxies.ClientIP(r)
}

// rateLimit wraps h, rejecting a client (keyed by IP) that exceeds rl with 429 +
// Retry-After. Applied to the credential-verification endpoints only.
func (s *Server) rateLimit(rl *rateLimiter, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !rl.allow(s.clientIP(r)) {
			w.Header().Set("Retry-After", strconv.Itoa(int(rl.window.Seconds())))
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		h(w, r)
	}
}
