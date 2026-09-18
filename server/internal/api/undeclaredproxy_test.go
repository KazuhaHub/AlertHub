package api

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// warnRecorder captures what the server logs, so the test can assert on the
// undeclared-proxy warning without parsing a formatted line.
type warnRecorder struct {
	mu   sync.Mutex
	msgs []string
}

func (h *warnRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (h *warnRecorder) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.msgs = append(h.msgs, r.Message)
	return nil
}
func (h *warnRecorder) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *warnRecorder) WithGroup(string) slog.Handler      { return h }
func (h *warnRecorder) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.msgs)
}

func captureWarnings(t *testing.T) *warnRecorder {
	t.Helper()
	rec := &warnRecorder{}
	prev := slog.Default()
	slog.SetDefault(slog.New(rec))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return rec
}

func forwardedFrom(peer, xff string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	r.RemoteAddr = peer
	r.Header.Set("X-Forwarded-For", xff)
	return r
}

// TestUndeclaredProxyIsReportedOnce is the signal this server did not have while
// its own rate limiter was keyed on the proxy: a forwarded request from a peer
// nobody declared is a deployment that is running wrong and looks fine.
//
// It must fire exactly once per process. The request that triggers it is an
// ordinary login attempt, so emitting it per request would bury the log rather
// than draw attention to the one line that matters.
func TestUndeclaredProxyIsReportedOnce(t *testing.T) {
	rec := captureWarnings(t)
	ts := newTestServer(t)
	ts.srv.TrustedProxies = mustTrustedProxies(t, "loopback")

	const stranger = "198.51.100.99:44444"
	for i := 0; i < 5; i++ {
		ts.srv.clientIP(forwardedFrom(stranger, "203.0.113.9"))
	}
	if got := rec.count(); got != 1 {
		t.Fatalf("undeclared proxy warned %d times for 5 requests, want exactly 1", got)
	}
}

// The other side, which a guard that only checked "did we warn" would miss
// entirely: a correctly configured deployment must stay quiet. A warning that
// fires on healthy traffic is one an operator learns to ignore.
func TestDeclaredProxyIsNotReported(t *testing.T) {
	rec := captureWarnings(t)
	ts := newTestServer(t)
	ts.srv.TrustedProxies = mustTrustedProxies(t, "loopback")

	// Peer is loopback (declared) and forwarding a client: the ordinary,
	// correctly configured case.
	ts.srv.clientIP(forwardedFrom("127.0.0.1:54321", "203.0.113.9"))
	// No proxy in front at all: no header to distrust.
	plain := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	plain.RemoteAddr = "198.51.100.99:44444"
	ts.srv.clientIP(plain)

	if got := rec.count(); got != 0 {
		t.Fatalf("warned %d times on correctly configured traffic, want 0: %v", got, rec.msgs)
	}
}

// TestUndeclaredProxyStillRefusesTheHeader pins the behaviour the warning sits
// beside: the warning is not permission. Believing a peer that was never
// declared would let any client choose its own address, and the audit trail is
// the record an investigator relies on.
func TestUndeclaredProxyStillRefusesTheHeader(t *testing.T) {
	rec := captureWarnings(t)
	ts := newTestServer(t)
	ts.srv.TrustedProxies = mustTrustedProxies(t, "loopback")

	// Both directions, because either alone is satisfied by a degenerate
	// implementation: "always return the peer" agrees with the first, and
	// "always believe the header" agrees with the second. Only the pair pins
	// that the decision turns on the peer and not on nothing.
	if got := ts.srv.clientIP(forwardedFrom("198.51.100.99:44444", "203.0.113.9")); got != "198.51.100.99" {
		t.Fatalf("undeclared peer: clientIP = %q, want the peer 198.51.100.99 -- the header must still be refused", got)
	}
	if got := ts.srv.clientIP(forwardedFrom("127.0.0.1:54321", "203.0.113.9")); got != "203.0.113.9" {
		t.Fatalf("declared peer: clientIP = %q, want the forwarded client 203.0.113.9 -- the header must still be honoured", got)
	}
	if rec.count() == 0 {
		t.Fatal("the refusal must be accompanied by the warning, or it is the same silence as before")
	}
}

func mustTrustedProxies(t *testing.T, spec string) TrustedProxies {
	t.Helper()
	tp, err := ParseTrustedProxies(spec)
	if err != nil {
		t.Fatalf("ParseTrustedProxies(%q): %v", spec, err)
	}
	return tp
}
