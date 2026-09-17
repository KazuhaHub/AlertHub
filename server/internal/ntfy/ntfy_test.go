package ntfy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/KazuhaHub/AlertHub/server/internal/alert"
)

type capture struct {
	mu   sync.Mutex
	msgs []msg
	auth []string
}

func (c *capture) handler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var m msg
	_ = json.Unmarshal(body, &m)
	c.mu.Lock()
	c.msgs = append(c.msgs, m)
	c.auth = append(c.auth, r.Header.Get("Authorization"))
	c.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func TestSelfHostedGetsAllSeveritiesPublicGetsOnlyLoud(t *testing.T) {
	self := &capture{}
	pub := &capture{}
	selfSrv := httptest.NewServer(http.HandlerFunc(self.handler))
	pubSrv := httptest.NewServer(http.HandlerFunc(pub.handler))
	defer selfSrv.Close()
	defer pubSrv.Close()

	p := New(Config{
		BaseURL:     selfSrv.URL,
		Token:       "tk_test",
		TopicPrefix: "alerthub-",
		PublicTopic: "ah-secret-emerg",
		PublicURL:   pubSrv.URL,
	})

	p.Publish(&alert.Alert{Severity: "notice", Category: "security", Title: "异地登录", Body: "b"})
	p.Publish(&alert.Alert{Severity: "emergency", Category: "earthquake", Title: "正在发生地震", Body: "震中42km", Action: "趴下，掩护，抓牢"})

	// self-hosted: both alerts
	if len(self.msgs) != 2 {
		t.Fatalf("self-hosted got %d msgs, want 2", len(self.msgs))
	}
	if self.msgs[0].Topic != "alerthub-security" || self.msgs[0].Priority != 2 {
		t.Errorf("notice self msg wrong: %+v", self.msgs[0])
	}
	if self.msgs[1].Topic != "alerthub-earthquake" || self.msgs[1].Priority != 5 {
		t.Errorf("emergency self msg wrong: %+v", self.msgs[1])
	}
	if !strings.Contains(self.msgs[1].Message, "趴下，掩护，抓牢") {
		t.Errorf("self emergency msg should append action, got %q", self.msgs[1].Message)
	}
	if want := "Bearer tk_test"; self.auth[0] != want {
		t.Errorf("self auth = %q, want %q", self.auth[0], want)
	}

	// public ntfy.sh: ONLY the emergency, generic + no PII (no Chinese title leaked)
	if len(pub.msgs) != 1 {
		t.Fatalf("public got %d msgs, want 1 (crit/emerg only)", len(pub.msgs))
	}
	if pub.msgs[0].Topic != "ah-secret-emerg" || pub.msgs[0].Priority != 5 {
		t.Errorf("public msg wrong: %+v", pub.msgs[0])
	}
	if pub.msgs[0].Title == "正在发生地震" || pub.msgs[0].Message == "震中42km" {
		t.Errorf("PII leaked to public ntfy.sh: %+v", pub.msgs[0])
	}
	if pub.auth[0] != "" {
		t.Errorf("public ntfy.sh must be tokenless, got auth %q", pub.auth[0])
	}
}

func TestDisabledIsNoOp(t *testing.T) {
	p := New(Config{}) // nothing configured
	if p.Enabled() {
		t.Fatal("expected disabled")
	}
	p.Publish(&alert.Alert{Severity: "emergency", Category: "fire", Title: "x"}) // must not panic
}
