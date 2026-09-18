package api

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// TrustedProxies is the set of peer addresses whose X-Forwarded-For header may
// be believed when deciding which client a request came from.
//
// It exists because the rate limiter keys on the client address, and SECURITY.md
// recommends terminating TLS at a reverse proxy. With no trusted proxies every
// request through such a proxy shares one peer address, so "10 attempts per
// minute per IP" across the five credential endpoints collapses into "10 per
// minute in total" -- which stops being a brute-force defence and becomes a
// denial-of-service lever, since one attacker spending the budget locks every
// other user out of logging in.
//
// The zero value trusts nothing and ignores X-Forwarded-For entirely, which is
// the behaviour of every release before this type existed.
type TrustedProxies struct {
	nets []*net.IPNet
}

// ParseTrustedProxies reads the ALERTHUB_TRUSTED_PROXIES form:
//
//	""          trust nothing; X-Forwarded-For is ignored (the default)
//	"none"      the same, written explicitly
//	"loopback"  127.0.0.0/8 and ::1, for a proxy on the same host
//	"10.0.0.0/8,192.168.1.7"
//	            an explicit list; bare addresses mean that single address
//
// There is deliberately no "trust everything" form. A proxy set that accepts any
// peer makes X-Forwarded-For attacker-controlled, which would let a single
// client mint unlimited rate-limit keys -- the opposite of what this is for.
func ParseTrustedProxies(spec string) (TrustedProxies, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || strings.EqualFold(spec, "none") {
		return TrustedProxies{}, nil
	}
	var tp TrustedProxies
	for _, raw := range strings.Split(spec, ",") {
		tok := strings.TrimSpace(raw)
		if tok == "" {
			continue
		}
		if strings.EqualFold(tok, "loopback") {
			for _, cidr := range []string{"127.0.0.0/8", "::1/128"} {
				_, n, err := net.ParseCIDR(cidr)
				if err != nil {
					return TrustedProxies{}, fmt.Errorf("loopback %q: %w", cidr, err)
				}
				tp.nets = append(tp.nets, n)
			}
			continue
		}
		if strings.EqualFold(tok, "all") || tok == "*" || tok == "0.0.0.0/0" || tok == "::/0" {
			return TrustedProxies{}, fmt.Errorf("%q would trust every peer, making X-Forwarded-For attacker-controlled; list the proxy addresses instead", tok)
		}
		if _, n, err := net.ParseCIDR(tok); err == nil {
			tp.nets = append(tp.nets, n)
			continue
		}
		ip := net.ParseIP(tok)
		if ip == nil {
			return TrustedProxies{}, fmt.Errorf("%q is neither an IP address nor a CIDR block", tok)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		tp.nets = append(tp.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return tp, nil
}

// Configured reports whether any proxy is trusted at all.
func (tp TrustedProxies) Configured() bool { return len(tp.nets) > 0 }

func (tp TrustedProxies) trusts(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range tp.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// hostOnly strips the port from a "host:port" peer address. A bare address is
// returned unchanged, which is what httptest and unix sockets produce.
func hostOnly(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// ForwardedFromUntrustedPeer reports whether the request carries
// X-Forwarded-For while arriving from a peer this set does not trust.
//
// That combination means there is a reverse proxy in front of this server and
// the server has not been told to believe it. Discarding the header is still the
// right response -- believing an unvouched-for peer would let anyone claim any
// address -- but staying silent about it is not, and silence is what let this
// server's own rate-limiter defect sit unnoticed: every request was attributed
// to the proxy, identically, and the column looked populated rather than wrong.
//
// This is the signal, not the response. It is reported per request and holds no
// state, so a caller that wants "has this ever happened" keeps its own flag.
func (tp TrustedProxies) ForwardedFromUntrustedPeer(r *http.Request) bool {
	if len(r.Header.Values("X-Forwarded-For")) == 0 {
		return false
	}
	return !tp.trusts(net.ParseIP(hostOnly(r.RemoteAddr)))
}

// ClientIP returns the address the rate limiter should key on.
//
// With no trusted proxies it is the TCP peer, unchanged. Otherwise the
// X-Forwarded-For chain is walked from right to left: each entry was appended by
// the hop to its right, so entries contributed by trusted hops are themselves
// trustworthy, and the first address that is NOT a trusted proxy is the client.
//
// Anything the walk cannot vouch for falls back to the peer address. That keeps
// a spoofed header from ever becoming the key: a client may write whatever it
// likes into X-Forwarded-For, but those values sit to the LEFT of the addresses
// the trusted proxies appended, so the walk stops before reaching them.
func (tp TrustedProxies) ClientIP(r *http.Request) string {
	peer := hostOnly(r.RemoteAddr)
	if !tp.Configured() || !tp.trusts(net.ParseIP(peer)) {
		return peer
	}
	for _, hop := range forwardedChain(r) {
		ip := net.ParseIP(hop)
		if ip == nil {
			// A hop this code cannot parse breaks the chain of custody: every
			// entry further left is unverifiable, so stop rather than guess.
			break
		}
		if !tp.trusts(ip) {
			return ip.String()
		}
	}
	return peer
}

// forwardedChain flattens every X-Forwarded-For header into one list, ordered
// RIGHT TO LEFT -- nearest hop first.
func forwardedChain(r *http.Request) []string {
	var chain []string
	for _, header := range r.Header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(header, ",") {
			if tok := strings.TrimSpace(part); tok != "" {
				chain = append(chain, hostOnly(tok))
			}
		}
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}
