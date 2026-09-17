package api

// Escalation ladder (SPEC-SAFETY §5), server side.
//
// An alert that nobody acknowledges is the failure this whole system exists to
// catch: it looks identical to a delivered one until someone checks. So for
// critical/emergency the server watches the ack roster and gets progressively
// louder — re-sending on the independent ntfy channel at rising priority, and
// finally marking the silent devices UNREACHABLE so a human goes and looks.
//
// SCOPE, stated honestly: SPEC-SAFETY §5 also asks for three SIGNED envelope
// fields (reissued_at / escalation_phase / requires_ack) so the CLIENT re-alarms
// on a phase advance. Those change the canonical form — schema v2 — and are not
// implemented here. What this delivers is the server-side half: escalation over
// the backup channel, the UNREACHABLE verdict, and the roster that tells an
// operator who to go find. §10 records the remainder.

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/KazuhaHub/AlertHub/server/internal/alert"
	"github.com/KazuhaHub/AlertHub/server/internal/metrics"
)

// Phase thresholds per SPEC-SAFETY §5. emergency escalates roughly twice as fast
// as critical, because the cost of a late response is not symmetric.
var escalationSchedule = map[string][3]time.Duration{
	"emergency": {15 * time.Second, 45 * time.Second, 2 * time.Minute},
	"critical":  {30 * time.Second, 90 * time.Second, 3 * time.Minute},
}

// EscalationState is what an operator needs to act: which phase an alert has
// reached and who is still silent.
type EscalationState struct {
	AlertID   string   `json:"alert_id"`
	Severity  string   `json:"severity"`
	Phase     int      `json:"phase"` // 0 = published, 1..3 = T1..T3
	StartedAt int64    `json:"started_at"`
	Pending   []string `json:"pending"`     // online, still not acknowledged
	Unreached []string `json:"unreachable"` // reached T3 without acknowledging
	Done      bool     `json:"done"`        // everyone acked, or cancelled/expired
	alert     *alert.Alert
	lastPhase time.Time
}

type escalator struct {
	mu    sync.Mutex
	items map[string]*EscalationState
}

func newEscalator() *escalator { return &escalator{items: map[string]*EscalationState{}} }

// TrackForAck starts the ladder for an alert that demands acknowledgement.
// notice/warning are informational and deliberately never escalate — escalating
// them would train people to ignore the ladder itself.
func (s *Server) TrackForAck(a *alert.Alert) {
	if a == nil || a.Type != "alert" {
		return
	}
	if _, ok := escalationSchedule[a.Severity]; !ok {
		return
	}
	if s.esc == nil {
		s.esc = newEscalator()
	}
	s.esc.mu.Lock()
	defer s.esc.mu.Unlock()
	s.esc.items[a.ID] = &EscalationState{
		AlertID: a.ID, Severity: a.Severity, StartedAt: time.Now().Unix(),
		alert: a, lastPhase: time.Now(),
	}
	slog.Info("escalation tracking started", "alert_id", a.ID, "severity", a.Severity)
}

// StopEscalation ends the ladder — used when an alert is cancelled, since a
// recalled alert must not keep nagging.
func (s *Server) StopEscalation(alertID string) {
	if s.esc == nil {
		return
	}
	s.esc.mu.Lock()
	defer s.esc.mu.Unlock()
	if st, ok := s.esc.items[alertID]; ok {
		st.Done = true
	}
}

// RunEscalator drives the ladder. It ticks rather than sleeping per-alert so a
// burst of alerts cannot spawn a goroutine each.
func (s *Server) RunEscalator(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.evalEscalations()
		}
	}
}

// evalEscalations advances any alert whose phase deadline has passed and which
// still has silent devices.
func (s *Server) evalEscalations() {
	if s.esc == nil {
		return
	}
	s.esc.mu.Lock()
	pending := make([]*EscalationState, 0, len(s.esc.items))
	for _, st := range s.esc.items {
		if !st.Done {
			pending = append(pending, st)
		}
	}
	s.esc.mu.Unlock()

	now := time.Now()
	for _, st := range pending {
		// Expiry ends the ladder: past TTL the alert is no longer actionable, and
		// nagging about a stale emergency is its own kind of false alarm.
		if now.Unix() > st.alert.IssuedAt+st.alert.TTL {
			s.esc.mu.Lock()
			st.Done = true
			s.esc.mu.Unlock()
			continue
		}
		silent := s.pendingDevices(st.AlertID)
		if len(silent) == 0 {
			s.esc.mu.Lock()
			st.Done = true
			st.Pending = nil
			s.esc.mu.Unlock()
			slog.Info("alert fully acknowledged", "alert_id", st.AlertID)
			continue
		}

		sched := escalationSchedule[st.Severity]
		next := st.Phase // 0-based; advance at most one phase per tick
		for i := st.Phase; i < 3; i++ {
			if now.Sub(time.Unix(st.StartedAt, 0)) >= sched[i] {
				next = i + 1
			}
		}
		s.esc.mu.Lock()
		st.Pending = silent
		if next > st.Phase {
			st.Phase = next
			st.lastPhase = now
			if next >= 3 {
				st.Unreached = silent
			}
		}
		phase := st.Phase
		s.esc.mu.Unlock()

		if next > 0 && now.Equal(st.lastPhase) {
			if phase >= 3 {
				slog.Error("devices UNREACHABLE — nobody acknowledged, go look",
					"alert_id", st.AlertID, "severity", st.Severity, "devices", silent)
			} else {
				slog.Warn("alert still unacknowledged — escalating",
					"alert_id", st.AlertID, "phase", phase, "pending", silent)
			}
			if s.Ntfy != nil {
				go s.Ntfy.Escalate(st.alert, phase, silent)
			}
			metrics.Escalations.WithLabelValues(st.Severity, strconv.Itoa(phase)).Inc()
		}
	}
}

// pendingDevices returns devices that are online but have not acknowledged.
// Offline devices are excluded on purpose: they are a delivery problem, already
// covered by the backup channel, not a person ignoring an instruction.
func (s *Server) pendingDevices(alertID string) []string {
	acked := map[string]bool{}
	if list, err := s.Store.ListAcks(s.DefaultOrgID, alertID); err == nil {
		for _, a := range list {
			acked[a.DeviceID] = true
		}
	}
	out := []string{}
	s.presenceMu.Lock()
	for id, p := range s.presence {
		if p.State == "online" && !acked[id] {
			out = append(out, id)
		}
	}
	s.presenceMu.Unlock()
	return out
}

// Escalations returns the live ladder state, newest first, for the roster view.
func (s *Server) Escalations() []EscalationState {
	if s.esc == nil {
		return []EscalationState{}
	}
	s.esc.mu.Lock()
	defer s.esc.mu.Unlock()
	out := make([]EscalationState, 0, len(s.esc.items))
	for _, st := range s.esc.items {
		out = append(out, *st)
	}
	return out
}

// GET /api/alerts/escalations — the operator's action list.
func (s *Server) handleEscalations(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Escalations())
}
