package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// postLoginVia sends a failing login the way a reverse proxy would deliver it:
// the TCP peer is the proxy, and the real client address is in X-Forwarded-For.
func postLoginVia(t *testing.T, ts *testServer, peer, xff string) int {
	t.Helper()
	body, err := json.Marshal(loginReq{UPN: "nobody", Password: "wrong"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	r.RemoteAddr = peer
	r.Header.Set("Content-Type", "application/json")
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	w := httptest.NewRecorder()
	ts.handler.ServeHTTP(w, r)
	return w.Code
}

func trustLoopback(t *testing.T, ts *testServer) {
	t.Helper()
	tp, err := ParseTrustedProxies("loopback")
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	ts.srv.TrustedProxies = tp
}

// TestRateLimit_BehindReverseProxy_KeepsPerClientBudgets is the deployment
// SECURITY.md describes: TLS terminated by a reverse proxy in front of the
// server. Keying the limiter on the TCP peer collapses "10 per minute per IP"
// into "10 per minute in total" across the five credential endpoints that share
// one limiter -- so the limiter stops being a brute-force defence and becomes a
// denial-of-service lever, because one attacker spending the budget locks every
// other user out of logging in.
func TestRateLimit_BehindReverseProxy_KeepsPerClientBudgets(t *testing.T) {
	ts := newTestServer(t)
	trustLoopback(t, ts)
	const proxy = "127.0.0.1:54321"

	for i := 0; i < 10; i++ {
		if code := postLoginVia(t, ts, proxy, "203.0.113.9"); code == http.StatusTooManyRequests {
			t.Fatalf("attacker attempt %d was throttled before the limit; test setup is wrong", i+1)
		}
	}
	if code := postLoginVia(t, ts, proxy, "198.51.100.7"); code == http.StatusTooManyRequests {
		t.Fatal("a second client was locked out by the first client's attempts: " +
			"behind a proxy the per-IP limiter has collapsed into a global one")
	}
}

// TestRateLimit_SpoofedForwardedForFromUntrustedPeerIsIgnored is the other half:
// trusting a header must not let a client mint unlimited rate-limit keys. A peer
// that is not a trusted proxy gets its own address used no matter what it claims.
func TestRateLimit_SpoofedForwardedForFromUntrustedPeerIsIgnored(t *testing.T) {
	ts := newTestServer(t)
	trustLoopback(t, ts)
	const attacker = "203.0.113.9:44444"

	got429 := false
	for i := 0; i < 12; i++ {
		// A fresh forged address on every request: if the header were believed,
		// each one would look like a brand-new client and never be throttled.
		code := postLoginVia(t, ts, attacker, "198.51.100."+string(rune('0'+i%10)))
		if code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("a peer that is not a trusted proxy must be keyed on its own address, " +
			"or X-Forwarded-For becomes an unlimited supply of rate-limit keys")
	}
}

// TestRateLimit_ForwardedChainStopsAtTheFirstUntrustedHop covers the walk itself:
// with two chained trusted proxies, the client is the rightmost address that is
// not one of them -- and addresses the client wrote itself, further left, are
// never reached.
func TestRateLimit_ForwardedChainStopsAtTheFirstUntrustedHop(t *testing.T) {
	tp, err := ParseTrustedProxies("loopback,10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	// Client forged "1.1.1.1", then the real client 203.0.113.9 was appended by
	// the outer proxy, then 10.1.2.3 by the inner one.
	r.Header.Set("X-Forwarded-For", "1.1.1.1, 203.0.113.9, 10.1.2.3")
	if got := tp.ClientIP(r); got != "203.0.113.9" {
		t.Fatalf("ClientIP = %q, want 203.0.113.9 (the first untrusted hop from the right)", got)
	}
}

// TestTrustedProxies_ZeroValueIgnoresForwardedFor pins the compatibility promise:
// unconfigured, the behaviour is exactly what it was before this type existed.
func TestTrustedProxies_ZeroValueIgnoresForwardedFor(t *testing.T) {
	var tp TrustedProxies
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := tp.ClientIP(r); got != "127.0.0.1" {
		t.Fatalf("ClientIP = %q, want the peer 127.0.0.1", got)
	}
}

func TestParseTrustedProxies(t *testing.T) {
	for _, tc := range []struct {
		spec       string
		wantErr    bool
		configured bool
	}{
		{"", false, false},
		{"none", false, false},
		{"NONE", false, false},
		{"loopback", false, true},
		{"10.0.0.0/8", false, true},
		{"192.168.1.7", false, true},
		{"loopback, 10.0.0.0/8 ,192.168.1.7", false, true},
		{"::1", false, true},
		{"all", true, false},
		{"*", true, false},
		{"0.0.0.0/0", true, false},
		{"::/0", true, false},
		{"not-an-address", true, false},
		{"10.0.0.0/99", true, false},
	} {
		tp, err := ParseTrustedProxies(tc.spec)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseTrustedProxies(%q) = nil error, want one", tc.spec)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseTrustedProxies(%q): %v", tc.spec, err)
			continue
		}
		if tp.Configured() != tc.configured {
			t.Errorf("ParseTrustedProxies(%q).Configured() = %v, want %v", tc.spec, tp.Configured(), tc.configured)
		}
	}
}

// TestAuditRecordsTheRealClientBehindAProxy: the audit trail keys on the same
// helper, so without a trusted-proxy set every entry records the proxy address
// and the trail loses the one field an investigator needs.
func TestAuditRecordsTheRealClientBehindAProxy(t *testing.T) {
	ts := newTestServer(t)
	trustLoopback(t, ts)
	if code := postLoginVia(t, ts, "127.0.0.1:54321", "203.0.113.9"); code != http.StatusUnauthorized {
		t.Fatalf("login = %d, want 401", code)
	}
	entries, err := ts.srv.Store.ListAudit(ts.srv.DefaultOrgID, 10)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("a failed login must be audited")
	}
	if got := entries[0].IP; got != "203.0.113.9" {
		t.Fatalf("audited IP = %q, want the real client 203.0.113.9", got)
	}
}
