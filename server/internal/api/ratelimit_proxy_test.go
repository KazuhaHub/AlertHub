package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KazuhaHub/authcore/clientip"
)

// The client-address logic this file used to test in isolation -- parsing the
// trusted-proxy spec, the zero value, and the right-to-left walk -- moved to
// authcore/clientip, which tests all three and verifies them by mutation rather
// than by passing. The unit-level cases were removed here rather than copied:
// duplicating them would mean two suites to update for one behaviour, and the
// copy in this repository would not be the one that fails when the package
// regresses.
//
// What stays is the wiring, which the package cannot test for AlertHub: that the
// credential limiter actually keys on the resolved address, that a spoofed
// header cannot mint keys, and that the audit trail records the same address the
// limiter used. Those exercise the walk end to end through the real handler, so
// the behaviour is still covered here even though its unit tests are elsewhere.

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
	ts.srv.TrustedProxies = clientip.Loopback()
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

// TestRateLimit_UnparseableHopFallsBackToThePeer is the wiring half of
// Report-Portal#15's fix, reached through the real handler: a chain the walk
// cannot verify must not hand the limiter an address nobody vouched for. The
// request carries a forged address to the left of a hop that does not parse, so
// believing anything past that hop would key the limiter on the attacker's
// chosen value.
func TestRateLimit_UnparseableHopFallsBackToThePeer(t *testing.T) {
	ts := newTestServer(t)
	trustLoopback(t, ts)

	// The peer is the trusted proxy; the chain is (right to left)
	// 127.0.0.1, then garbage. Believing past the garbage would return 9.9.9.9.
	const peer = "127.0.0.1:54321"
	for i := 0; i < 12; i++ {
		// A different forged address each time, so a limiter keyed on the forged
		// value would never block and the budget would never be spent.
		forged := "9.9.9." + string(rune('0'+i%10))
		if code := postLoginVia(t, ts, peer, forged+", garbage, 127.0.0.1"); code == http.StatusTooManyRequests {
			return // keyed on the peer, as it must be
		}
	}
	t.Fatal("a chain with an unparseable hop let the client mint a fresh limiter key per request")
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
