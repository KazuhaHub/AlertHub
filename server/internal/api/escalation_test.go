package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/KazuhaHub/AlertHub/server/internal/alert"
)

func ackAlert(sev string, ttl int64) *alert.Alert {
	return &alert.Alert{
		SchemaVersion: alert.SchemaVersion, ID: "esc-" + sev, Type: "alert",
		Category: "fire", Severity: sev, Title: "t",
		IssuedAt: time.Now().Unix(), TTL: ttl,
	}
}

// Only critical/emergency escalate. Escalating a notice would train people to
// ignore the ladder, which costs more than the notice is worth.
func TestEscalation_OnlyTracksAckRequiringSeverities(t *testing.T) {
	ts := newTestServer(t)
	for _, sev := range []string{"notice", "warning"} {
		ts.srv.TrackForAck(ackAlert(sev, 600))
	}
	if n := len(ts.srv.Escalations()); n != 0 {
		t.Fatalf("%d informational alerts entered the ladder, want 0", n)
	}
	ts.srv.TrackForAck(ackAlert("emergency", 600))
	if n := len(ts.srv.Escalations()); n != 1 {
		t.Fatalf("emergency should be tracked, got %d entries", n)
	}
}

// TestEscalation_AdvancesWhileSilent is the core behaviour: an online device that
// never acknowledges drives the alert up the phases.
func TestEscalation_AdvancesWhileSilent(t *testing.T) {
	ts := newTestServer(t)
	ts.srv.OnPresence("status/dev-1", []byte(`{"device_id":"dev-1","state":"online"}`))

	a := ackAlert("emergency", 600)
	ts.srv.TrackForAck(a)
	// Backdate the start so the T1 threshold (15s for emergency) has passed.
	ts.srv.esc.mu.Lock()
	ts.srv.esc.items[a.ID].StartedAt = time.Now().Add(-20 * time.Second).Unix()
	ts.srv.esc.mu.Unlock()

	ts.srv.evalEscalations()
	st := ts.srv.Escalations()[0]
	if st.Phase < 1 {
		t.Fatalf("phase = %d after T1 elapsed with nobody acking, want >= 1", st.Phase)
	}
	if len(st.Pending) != 1 || st.Pending[0] != "dev-1" {
		t.Fatalf("pending = %v, want [dev-1]", st.Pending)
	}
}

// An acknowledgement must stop the ladder — continuing to escalate after someone
// responded is exactly the false alarm that erodes trust.
func TestEscalation_StopsOnAck(t *testing.T) {
	ts := newTestServer(t)
	ts.srv.OnPresence("status/dev-1", []byte(`{"device_id":"dev-1","state":"online"}`))
	a := ackAlert("critical", 600)
	ts.srv.TrackForAck(a)

	ts.srv.OnAck("alerts/"+a.ID+"/ack/dev-1", []byte(`{"ack_at":1}`))
	ts.srv.evalEscalations()

	st := ts.srv.Escalations()[0]
	if !st.Done {
		t.Fatal("ladder must finish once every online device has acknowledged")
	}
	if len(st.Pending) != 0 {
		t.Fatalf("pending = %v, want empty", st.Pending)
	}
}

// Offline devices are a delivery problem already covered by the backup channel,
// not a person ignoring an instruction — they must not hold the ladder open.
func TestEscalation_OfflineDevicesDoNotBlock(t *testing.T) {
	ts := newTestServer(t)
	ts.srv.OnPresence("status/gone", []byte(`{"device_id":"gone","state":"offline"}`))
	a := ackAlert("emergency", 600)
	ts.srv.TrackForAck(a)

	ts.srv.evalEscalations()
	if st := ts.srv.Escalations()[0]; !st.Done {
		t.Fatalf("only an offline device present, ladder should finish; got %+v", st)
	}
}

// A recalled alert must stop nagging immediately.
func TestEscalation_StopsOnCancel(t *testing.T) {
	ts := newTestServer(t)
	ts.srv.OnPresence("status/dev-1", []byte(`{"device_id":"dev-1","state":"online"}`))
	a := ackAlert("emergency", 600)
	ts.srv.TrackForAck(a)
	ts.srv.StopEscalation(a.ID)
	ts.srv.evalEscalations()
	if st := ts.srv.Escalations()[0]; !st.Done {
		t.Fatal("cancelling an alert must end its escalation")
	}
}

// Past its TTL an alert is no longer actionable; nagging about a stale emergency
// is its own kind of false alarm.
func TestEscalation_StopsAtExpiry(t *testing.T) {
	ts := newTestServer(t)
	ts.srv.OnPresence("status/dev-1", []byte(`{"device_id":"dev-1","state":"online"}`))
	a := ackAlert("emergency", 1)
	a.IssuedAt = time.Now().Add(-time.Hour).Unix()
	ts.srv.TrackForAck(a)

	ts.srv.evalEscalations()
	if st := ts.srv.Escalations()[0]; !st.Done {
		t.Fatal("an expired alert must stop escalating")
	}
}

// TestEscalation_T3MarksUnreachable: by the last phase nobody has responded, and
// the operator needs a name to go find.
func TestEscalation_T3MarksUnreachable(t *testing.T) {
	ts := newTestServer(t)
	ts.srv.OnPresence("status/dev-1", []byte(`{"device_id":"dev-1","state":"online"}`))
	a := ackAlert("emergency", 3600)
	ts.srv.TrackForAck(a)
	ts.srv.esc.mu.Lock()
	ts.srv.esc.items[a.ID].StartedAt = time.Now().Add(-10 * time.Minute).Unix()
	ts.srv.esc.mu.Unlock()

	ts.srv.evalEscalations()
	st := ts.srv.Escalations()[0]
	if st.Phase != 3 {
		t.Fatalf("phase = %d after all thresholds passed, want 3", st.Phase)
	}
	if len(st.Unreached) != 1 || st.Unreached[0] != "dev-1" {
		t.Fatalf("unreachable = %v, want [dev-1]", st.Unreached)
	}
}

// emergency must escalate faster than critical — the cost of a late response is
// not symmetric between them.
func TestEscalation_EmergencyOutpacesCritical(t *testing.T) {
	e, c := escalationSchedule["emergency"], escalationSchedule["critical"]
	for i := 0; i < 3; i++ {
		if e[i] >= c[i] {
			t.Errorf("phase %d: emergency %s must be sooner than critical %s", i+1, e[i], c[i])
		}
	}
}

func TestEscalations_Endpoint(t *testing.T) {
	ts := newTestServer(t)
	ts.srv.TrackForAck(ackAlert("critical", 600))

	if w := ts.req(t, http.MethodGet, "/api/alerts/escalations", nil, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauth = %d, want 401", w.Code)
	}
	w := ts.req(t, http.MethodGet, "/api/alerts/escalations", nil, adminHdr())
	if w.Code != http.StatusOK {
		t.Fatalf("escalations = %d", w.Code)
	}
	var got []EscalationState
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].Severity != "critical" {
		t.Fatalf("got %+v", got)
	}
}
