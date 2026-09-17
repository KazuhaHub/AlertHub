package siem

// Syslog transport (RFC 5424) for the audit trail.
//
// Many SIEMs ingest syslog and nothing else — an HTTP webhook is a modern
// convenience, not the lingua franca. Supporting both is the difference between
// "you can integrate this" and "you can integrate this if you also run a shim".
//
// Facility 13 is "log audit" in RFC 5424 §6.2.1, which is precisely what this
// stream is; using it means a collector routes these correctly with no rules.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/KazuhaHub/AlertHub/server/internal/store"
)

const (
	facilityLogAudit = 13
	sevNotice        = 5 // an ordinary recorded action
	sevWarning       = 4 // something a reviewer should look at
)

type syslogSink struct {
	network string // "udp" | "tcp"
	addr    string
	host    string

	mu   sync.Mutex
	conn net.Conn
}

func newSyslogSink(raw string) (*syslogSink, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	network := "udp"
	if strings.HasSuffix(u.Scheme, "+tcp") {
		network = "tcp"
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "-"
	}
	addr := u.Host
	if addr == "" {
		return nil, fmt.Errorf("siem: syslog URL %q has no host:port", raw)
	}
	return &syslogSink{network: network, addr: addr, host: host}, nil
}

// dial reuses the connection for TCP (a new connection per batch would be
// wasteful and can exhaust ports), and reconnects when it breaks.
func (s *syslogSink) dial() (net.Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		return s.conn, nil
	}
	c, err := net.DialTimeout(s.network, s.addr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	s.conn = c
	return c, nil
}

func (s *syslogSink) drop() {
	s.mu.Lock()
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}
	s.mu.Unlock()
}

// Ship writes one RFC 5424 line per entry.
func (s *syslogSink) Ship(ctx context.Context, entries []store.AuditEntry) error {
	conn, err := s.dial()
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(dl)
	} else {
		_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	}
	for _, e := range entries {
		if _, err := conn.Write([]byte(formatRFC5424(s.host, e))); err != nil {
			// Drop the connection so the next attempt redials; the cursor has not
			// advanced, so this batch replays rather than being lost.
			s.drop()
			return err
		}
	}
	return nil
}

// formatRFC5424 renders one audit entry as a syslog line.
//
// The structured-data block carries the fields a SIEM will actually filter on,
// and the message carries the JSON entry so nothing is lost to a collector that
// only stores the text.
func formatRFC5424(host string, e store.AuditEntry) string {
	sev := sevNotice
	if strings.Contains(e.Action, "failed") || strings.HasPrefix(e.Action, "audit.") {
		sev = sevWarning
	}
	pri := facilityLogAudit*8 + sev
	ts := time.Unix(e.At, 0).UTC().Format(time.RFC3339)

	// SD-PARAM values escape ", \ and ] per RFC 5424 §6.3.3.
	sd := fmt.Sprintf(
		`[alerthub@0 action="%s" actor_type="%s" actor="%s" target="%s" org="%d" ip="%s" hash="%s"]`,
		sdEscape(e.Action), sdEscape(e.ActorType), sdEscape(e.ActorName),
		sdEscape(e.TargetID), e.OrgID, sdEscape(e.IP), sdEscape(e.Hash))

	body, _ := json.Marshal(e)
	// A trailing newline frames the message for TCP collectors; harmless on UDP,
	// where each datagram is already a record.
	return fmt.Sprintf("<%d>1 %s %s alerthub - %s %s %s\n",
		pri, ts, host, sdEscape(e.Action), sd, string(body))
}

func sdEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`)
	// Newlines would break the one-record-per-line framing TCP collectors rely on.
	return r.Replace(strings.NewReplacer("\n", " ", "\r", " ").Replace(s))
}
