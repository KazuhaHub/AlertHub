// Package ntfy is the INDEPENDENT backup delivery channel (SPEC-SAFETY §4).
// The Go server dual-publishes alerts here in addition to MQTT: self-hosted ntfy
// for all severities (full content), and public ntfy.sh for critical/emergency
// only (generic, PII-free) so phones are reached even if the home server/LAN dies.
//
// This is an UNTRUSTED, one-way nudge channel: ntfy.sh messages are unsigned and
// third-party-visible, so they are human-actionable only ("open AlertHub / heed
// official channels") and never carry PII or trigger automated actions. The
// trust anchor remains the Ed25519-signed MQTT path.
package ntfy

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/KazuhaHub/AlertHub/server/internal/alert"
)

type Config struct {
	BaseURL     string // self-hosted base, e.g. https://ntfy.home.example.jp ; empty = self-host disabled
	Token       string // bearer token for protected self-hosted topics
	TopicPrefix string // self-hosted topic = TopicPrefix + category (e.g. "alerthub-earthquake")
	PublicTopic string // ntfy.sh fallback topic (unguessable) for crit/emerg ; empty = no public fallback
	PublicURL   string // default https://ntfy.sh
}

type Publisher struct {
	cfg    Config
	client *http.Client
}

func New(cfg Config) *Publisher {
	if cfg.PublicURL == "" {
		cfg.PublicURL = "https://ntfy.sh"
	}
	if cfg.TopicPrefix == "" {
		cfg.TopicPrefix = "alerthub-"
	}
	return &Publisher{cfg: cfg, client: &http.Client{Timeout: 4 * time.Second}}
}

func (p *Publisher) Enabled() bool { return p.cfg.BaseURL != "" || p.cfg.PublicTopic != "" }

type msg struct {
	Topic    string   `json:"topic"`
	Title    string   `json:"title"`
	Message  string   `json:"message"`
	Priority int      `json:"priority"`
	Tags     []string `json:"tags,omitempty"`
	Click    string   `json:"click,omitempty"`
}

func priorityFor(sev string) int {
	switch sev {
	case "emergency", "critical":
		return 5
	case "warning":
		return 3
	default:
		return 2
	}
}

func tagsFor(sev, cat string) []string {
	switch sev {
	case "emergency":
		return []string{"rotating_light", "siren", cat}
	case "critical":
		return []string{"warning", cat}
	default:
		return []string{"information_source", cat}
	}
}

// Publish fans an alert out to ntfy. Safe to call in a goroutine; never blocks the
// MQTT/sign hot path. No-op if ntfy is not configured.
// Escalate re-sends an unacknowledged alert at a raised priority (SPEC-SAFETY
// §5, T1/T2/T3). It is deliberately separate from Publish: the message says
// "still unacknowledged", which is a different thing to say than the original
// alert, and it must reach the loudest channel available even when the original
// went out quietly.
func (p *Publisher) Escalate(a *alert.Alert, phase int, pending []string) {
	if !p.Enabled() {
		return
	}
	title := "⚠ 仍未确认 · " + a.Title
	body := a.Body
	if len(pending) > 0 {
		body += "  未确认设备: " + strings.Join(pending, ", ")
	}
	// Priority climbs with the phase and tops out at ntfy's max: by T3 nobody has
	// responded, so this is the last thing that will make a phone make noise.
	prio := 4 + phase
	if prio > 5 {
		prio = 5
	}
	tags := []string{"rotating_light", "bangbang"}
	if p.cfg.BaseURL != "" {
		p.post(p.cfg.BaseURL, p.cfg.Token, msg{
			Topic: p.cfg.TopicPrefix + a.Severity, Title: title, Message: body,
			Priority: prio, Tags: tags,
		})
	}
	// The public relay carries no device names — it is a third-party host, and an
	// escalation is not a reason to start leaking the roster to it.
	if p.cfg.PublicTopic != "" {
		p.post("https://ntfy.sh", "", msg{
			Topic: p.cfg.PublicTopic, Title: title, Message: a.Body,
			Priority: prio, Tags: tags,
		})
	}
}

func (p *Publisher) Publish(a *alert.Alert) {
	if !p.Enabled() {
		return
	}
	sev := a.Severity

	// Self-hosted: all severities, full (private) content.
	if p.cfg.BaseURL != "" {
		topic := p.cfg.TopicPrefix + a.Category
		body := a.Body
		if a.Action != "" {
			body += "  →  " + a.Action
		}
		p.post(p.cfg.BaseURL, p.cfg.Token, msg{
			Topic: topic, Title: a.Title, Message: body,
			Priority: priorityFor(sev), Tags: tagsFor(sev, a.Category),
		})
	}

	// ntfy.sh fallback: critical/emergency only, GENERIC + PII-free.
	if p.cfg.PublicTopic != "" && (sev == "critical" || sev == "emergency") {
		p.post(p.cfg.PublicURL, "", msg{
			Topic:    p.cfg.PublicTopic,
			Title:    "AlertHub: " + genericTitle(a.Category, sev),
			Message:  "Open AlertHub / heed official channels (cell broadcast, smoke alarms).",
			Priority: 5, Tags: tagsFor(sev, a.Category),
		})
	}
}

func genericTitle(cat, sev string) string {
	switch cat {
	case "earthquake":
		return "EARTHQUAKE — strong shaking"
	case "fire":
		return "FIRE / SMOKE alert"
	case "weather":
		return "WEATHER emergency"
	default:
		return sev + " alert"
	}
}

func (p *Publisher) post(base, token string, m msg) {
	buf, _ := json.Marshal(m)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, base+"/", bytes.NewReader(buf))
	if err != nil {
		log.Printf("ntfy: build req: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		log.Printf("ntfy: post to %s (topic %s): %v", base, m.Topic, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("ntfy: post to %s (topic %s): status %d", base, m.Topic, resp.StatusCode)
	}
}
