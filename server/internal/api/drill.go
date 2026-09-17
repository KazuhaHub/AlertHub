package api

// Weekly drill (SPEC-SAFETY §3.4): prove the chain still works BEFORE it is
// needed. A system that has not delivered an alert in three months is not known
// to be working — it is only untested, and those look identical until the day
// they differ.
//
// The drill publishes a REAL alert through the ordinary path (sign → broker →
// client accept gate → ack). Anything less would test the test harness rather
// than the system: a drill that bypasses signing would still pass with a broken
// key, which is precisely the failure worth catching.

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/KazuhaHub/AlertHub/server/internal/alert"
	"github.com/KazuhaHub/AlertHub/server/internal/store"
)

// DrillConfig controls when the drill fires and how long it waits for answers.
type DrillConfig struct {
	Enabled  bool
	Weekday  time.Weekday
	Hour     int
	Minute   int
	Loc      *time.Location
	Window   time.Duration // how long devices have to acknowledge
	Severity string        // warning by default; quarterly critical is a manual call
}

// DefaultDrillConfig is Sunday 10:00 JST with a 10-minute collection window,
// per §3.4.
func DefaultDrillConfig() DrillConfig {
	jst, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		jst = time.FixedZone("JST", 9*3600)
	}
	return DrillConfig{
		Weekday: time.Sunday, Hour: 10, Minute: 0, Loc: jst,
		Window: 10 * time.Minute, Severity: "warning",
	}
}

// RunDrills fires the scheduled drill. It checks the wall clock each minute
// rather than sleeping until the next occurrence, so a laptop that suspends over
// the scheduled moment still runs the drill when it wakes within the same minute
// window, instead of silently skipping a week.
func (s *Server) RunDrills(ctx context.Context, cfg DrillConfig) {
	if !cfg.Enabled {
		return
	}
	if cfg.Loc == nil {
		cfg.Loc = time.UTC
	}
	if cfg.Window <= 0 {
		cfg.Window = 10 * time.Minute
	}
	if cfg.Severity == "" {
		cfg.Severity = "warning"
	}
	slog.Info("weekly drill scheduled",
		"weekday", cfg.Weekday.String(), "at", cfg.Loc.String(),
		"hour", cfg.Hour, "minute", cfg.Minute, "window", cfg.Window.String())

	t := time.NewTicker(time.Minute)
	defer t.Stop()
	var lastRun string
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now().In(cfg.Loc)
			if now.Weekday() != cfg.Weekday || now.Hour() != cfg.Hour || now.Minute() != cfg.Minute {
				continue
			}
			// Guard against firing twice inside the same minute.
			stamp := now.Format("2006-01-02T15:04")
			if stamp == lastRun {
				continue
			}
			lastRun = stamp
			go s.RunDrillOnce(ctx, cfg)
		}
	}
}

// RunDrillOnce publishes one drill alert, waits the collection window, and
// records who answered. Exported so an operator can trigger a drill on demand
// rather than waiting a week to test a change.
func (s *Server) RunDrillOnce(ctx context.Context, cfg DrillConfig) store.DrillResult {
	// Who is expected to answer: everyone online at the moment it fires. Devices
	// that are offline are not failures here — §3.4 says to re-test them when they
	// next appear, not to fail the whole drill for being asleep.
	expected := s.onlineDevices()

	a := &alert.Alert{
		SchemaVersion: alert.SchemaVersion,
		ID:            alert.NewID(),
		Type:          "alert",
		Category:      "system",
		Severity:      cfg.Severity,
		Title:         "🧪 演练 · 这是一次测试",
		Body:          "这是例行演练，不是真实警报。请点击确认，以证明这台设备在真警报时会响。",
		Action:        "点击确认",
		Source:        "drill",
		IssuedAt:      time.Now().Unix(),
		TTL:           int64(cfg.Window.Seconds()) + 60,
		Nonce:         alert.NewNonce(),
	}
	if err := s.PublishAlert(a, s.DefaultOrgID); err != nil {
		slog.Error("drill publish failed — the drill itself could not run", "err", err)
		return store.DrillResult{}
	}
	slog.Info("drill started", "alert_id", a.ID, "expected", len(expected), "window", cfg.Window.String())

	select {
	case <-ctx.Done():
		return store.DrillResult{}
	case <-time.After(cfg.Window):
	}

	acked := map[string]bool{}
	if list, err := s.Store.ListAcks(s.DefaultOrgID, a.ID); err == nil {
		for _, k := range list {
			acked[k.DeviceID] = true
		}
	}
	missed := []string{}
	for _, id := range expected {
		if !acked[id] {
			missed = append(missed, id)
		}
	}
	res := store.DrillResult{
		OrgID: s.DefaultOrgID, At: time.Now().Unix(), AlertID: a.ID, Severity: cfg.Severity,
		Expected: len(expected), Acked: len(expected) - len(missed),
		Missed: strings.Join(missed, ","), Passed: len(missed) == 0,
	}
	if err := s.Store.RecordDrill(res); err != nil {
		slog.Error("recording drill result failed", "err", err)
	}
	s.auditSystem(s.DefaultOrgID, "drill.run", "alert", a.ID,
		"drill "+map[bool]string{true: "PASS", false: "FAIL"}[res.Passed])

	if res.Passed {
		slog.Info("drill PASSED", "acked", res.Acked, "expected", res.Expected)
	} else {
		// Deliberately notify ADMINS only, never the whole roster: a drill that
		// spams everyone every week is worse than no drill, because people learn
		// to dismiss the channel it arrives on.
		slog.Error("drill FAILED — these devices may not alarm for real",
			"missed", missed, "acked", res.Acked, "expected", res.Expected)
		s.notifyDrillFailure(res, missed)
	}
	return res
}

// notifyDrillFailure tells the operator, over the independent channel, that a
// device did not answer.
func (s *Server) notifyDrillFailure(res store.DrillResult, missed []string) {
	if s.Ntfy == nil {
		return
	}
	a := &alert.Alert{
		SchemaVersion: alert.SchemaVersion, ID: "drill-fail-" + res.AlertID,
		Type: "alert", Category: "system", Severity: "warning",
		Title:  "演练未通过：有设备未确认",
		Body:   "未确认设备: " + strings.Join(missed, ", ") + " —— 它们在真实警报时可能不会响，请检查。",
		Action: "检查这些设备", Source: "drill", IssuedAt: time.Now().Unix(),
		TTL: 3600, Nonce: alert.NewNonce(),
	}
	alert.Sign(a, s.Priv)
	go s.Ntfy.Publish(a)
}

func (s *Server) onlineDevices() []string {
	out := []string{}
	s.presenceMu.Lock()
	for id, p := range s.presence {
		if p.State == "online" {
			out = append(out, id)
		}
	}
	s.presenceMu.Unlock()
	return out
}

// GET /api/drills — drill history, newest first. The trend is the point: a device
// that missed the last three drills is saying something one run cannot.
func (s *Server) handleDrills(w http.ResponseWriter, r *http.Request) {
	list, err := s.Store.ListDrills(s.orgFor(r), 50)
	if err != nil {
		http.Error(w, "drill list failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, list)
}

// POST /api/drills/run — fire one now. Waiting a week to test a change is not a
// workable feedback loop, so an operator can trigger it on demand.
func (s *Server) handleDrillRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	cfg := s.DrillCfg
	// A manual drill uses a short window: the operator is watching right now.
	cfg.Window = 30 * time.Second
	s.audit(r, s.orgFor(r), "drill.run", "drill", "", "manual drill triggered")
	go s.RunDrillOnce(context.Background(), cfg)
	w.WriteHeader(http.StatusAccepted)
	writeJSON(w, map[string]any{"started": true, "window_seconds": int(cfg.Window.Seconds())})
}
