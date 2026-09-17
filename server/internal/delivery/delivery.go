// Package delivery is AlertHub's durable, at-least-once delivery pipeline: a
// transactional outbox (store.delivery_jobs) drained by a worker. PublishAlert
// enqueues one job per (alert, channel, target); the worker claims due jobs, calls
// the channel Sender, and marks them sent or reschedules with exponential backoff
// until max_attempts, then dead-letters (fail-loud). Unlike fire-and-forget, a job
// survives process restarts and transient channel outages. Works on SQLite and
// PostgreSQL; the Postgres claim uses FOR UPDATE SKIP LOCKED for multi-worker safety.
//
// This supersedes the in-proc channels.Dispatcher for webhook/email. (River, the
// Postgres-only job queue in ARCHITECTURE §6, remains an option for the very-high-
// scale Enterprise path; this built-in outbox serves BOTH tiers from one code path.)
package delivery

import (
	"context"
	"log"
	"log/slog"
	"time"

	"github.com/KazuhaHub/AlertHub/server/internal/alert"
	"github.com/KazuhaHub/AlertHub/server/internal/metrics"
	"github.com/KazuhaHub/AlertHub/server/internal/store"
)

// Sender delivers an alert payload to one target on a specific channel.
type Sender interface {
	Channel() string                                        // "webhook" | "email" | …
	Targets(a *alert.Alert) []string                        // recipients (severity-filtered) for this alert
	Send(ctx context.Context, target, payload string) error // deliver; error = transient/retry
}

type Config struct {
	MaxAttempts  int
	BaseBackoff  time.Duration
	MaxBackoff   time.Duration
	Lease        time.Duration // crash-safety lease applied on claim
	Batch        int
	PollInterval time.Duration
	SendTimeout  time.Duration
}

func (c *Config) withDefaults() {
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 6
	}
	if c.BaseBackoff <= 0 {
		c.BaseBackoff = 2 * time.Second
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = 5 * time.Minute
	}
	if c.Lease <= 0 {
		c.Lease = time.Minute
	}
	if c.Batch <= 0 {
		c.Batch = 50
	}
	if c.PollInterval <= 0 {
		c.PollInterval = time.Second
	}
	if c.SendTimeout <= 0 {
		c.SendTimeout = 10 * time.Second
	}
}

type Manager struct {
	st      *store.Store
	senders []Sender
	cfg     Config
	now     func() time.Time // injectable clock (tests)
}

func New(st *store.Store, cfg Config, senders ...Sender) *Manager {
	cfg.withDefaults()
	return &Manager{st: st, senders: senders, cfg: cfg, now: time.Now}
}

// Enabled reports whether any channel is configured.
func (m *Manager) Enabled() bool { return m != nil && len(m.senders) > 0 }

// Enqueue writes durable jobs for every (channel, target) this alert routes to.
// Fast (a few INSERTs); safe to call on the publish hot path. Idempotent per alert.
func (m *Manager) Enqueue(a *alert.Alert, orgID int64, payload string) {
	now := m.now().Unix()
	for _, s := range m.senders {
		for _, t := range s.Targets(a) {
			ins, err := m.st.EnqueueDelivery(store.DeliveryJob{
				OrgID: orgID, AlertID: a.ID, Channel: s.Channel(), Target: t,
				Payload: payload, Severity: a.Severity, MaxAttempts: m.cfg.MaxAttempts,
			}, now)
			if err != nil {
				log.Printf("delivery enqueue %s/%s: %v", s.Channel(), t, err)
				continue
			}
			if ins {
				metrics.DeliveryEnqueued.WithLabelValues(s.Channel()).Inc()
			}
		}
	}
}

// RunWorker drains the outbox on a ticker until ctx is cancelled.
func (m *Manager) RunWorker(ctx context.Context) {
	t := time.NewTicker(m.cfg.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for { // drain: keep claiming while batches come back full
				if n := m.processBatch(ctx, m.now()); n < m.cfg.Batch {
					break
				}
			}
		}
	}
}

// processBatch claims and delivers one batch of due jobs. Returns the count claimed.
func (m *Manager) processBatch(ctx context.Context, nowT time.Time) int {
	now := nowT.Unix()
	jobs, err := m.st.ClaimDueDeliveries(now, int64(m.cfg.Lease.Seconds()), m.cfg.Batch)
	if err != nil {
		log.Printf("delivery claim: %v", err)
		return 0
	}
	for _, j := range jobs {
		m.deliver(ctx, j, now)
	}
	return len(jobs)
}

func (m *Manager) deliver(ctx context.Context, j store.DeliveryJob, now int64) {
	s := m.senderFor(j.Channel)
	if s == nil {
		_ = m.st.MarkDeliveryDead(j.ID, "no sender for channel "+j.Channel, now)
		metrics.DeliveryAttempts.WithLabelValues(j.Channel, "dead").Inc()
		return
	}
	cctx, cancel := context.WithTimeout(ctx, m.cfg.SendTimeout)
	defer cancel()
	err := s.Send(cctx, j.Target, j.Payload)
	// NB: a worker crash between a successful Send and MarkDeliverySent leaves the
	// job 'pending', so it is re-sent after the lease expires — at-least-once by
	// design (receivers must dedup on alert id; the envelope carries it). Below we
	// surface any state-write failure loudly instead of letting metrics drift from
	// the DB silently.
	switch {
	case err == nil:
		if werr := m.st.MarkDeliverySent(j.ID, now); werr != nil {
			log.Printf("delivery: MarkDeliverySent id=%d failed (will re-send after lease): %v", j.ID, werr)
			return // do NOT record 'sent' — DB disagrees; the lease will retry
		}
		metrics.DeliveryAttempts.WithLabelValues(j.Channel, "sent").Inc()
	case j.Attempts >= j.MaxAttempts:
		if werr := m.st.MarkDeliveryDead(j.ID, err.Error(), now); werr != nil {
			log.Printf("delivery: MarkDeliveryDead id=%d failed (job will retry, not dead-lettered): %v", j.ID, werr)
			return
		}
		metrics.DeliveryAttempts.WithLabelValues(j.Channel, "dead").Inc()
		// Dead-letter is a fail-loud signal: this alert did NOT reach this target.
		slog.Error("delivery dead-letter",
			"alert_id", j.AlertID, "channel", j.Channel, "target", j.Target,
			"attempts", j.Attempts, "severity", j.Severity, "err", err)
	default:
		next := now + int64(m.backoff(j.Attempts)/time.Second)
		if werr := m.st.RescheduleDelivery(j.ID, next, err.Error(), now); werr != nil {
			log.Printf("delivery: RescheduleDelivery id=%d failed (lease still governs retry): %v", j.ID, werr)
			return
		}
		metrics.DeliveryAttempts.WithLabelValues(j.Channel, "retry").Inc()
	}
}

// backoff returns the delay before the next retry: BaseBackoff·2^(attempts-1),
// capped at MaxBackoff (attempts is 1-based).
func (m *Manager) backoff(attempts int) time.Duration {
	d := m.cfg.BaseBackoff
	for i := 1; i < attempts; i++ {
		d *= 2
		if d >= m.cfg.MaxBackoff {
			return m.cfg.MaxBackoff
		}
	}
	return d
}

func (m *Manager) senderFor(ch string) Sender {
	for _, s := range m.senders {
		if s.Channel() == ch {
			return s
		}
	}
	return nil
}
