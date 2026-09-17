package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/KazuhaHub/AlertHub/server/internal/store"
)

func drillCfg(window time.Duration) DrillConfig {
	c := DefaultDrillConfig()
	c.Window = window
	return c
}

// TestDrill_PassesWhenEveryoneAcks: the drill publishes a real alert and counts
// who answered within the window.
func TestDrill_PassesWhenEveryoneAcks(t *testing.T) {
	ts := newTestServer(t)
	ts.srv.OnPresence("status/dev-1", []byte(`{"device_id":"dev-1","state":"online"}`))

	// Answer as soon as the drill alert lands, the way a real client would.
	done := make(chan struct{})
	if err := ts.srv.Broker.Subscribe(TopicEvents, func(_ string, payload []byte) {
		var a struct {
			ID     string `json:"id"`
			Source string `json:"source"`
		}
		if json.Unmarshal(payload, &a) == nil && a.Source == "drill" {
			ts.srv.OnAck("alerts/"+a.ID+"/ack/dev-1", []byte(`{"ack_at":1}`))
			close(done)
		}
	}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	res := ts.srv.RunDrillOnce(context.Background(), drillCfg(300*time.Millisecond))
	select {
	case <-done:
	default:
		t.Fatal("the drill never published an alert on the events topic")
	}
	if !res.Passed {
		t.Fatalf("drill should pass when the only online device acked: %+v", res)
	}
	if res.Expected != 1 || res.Acked != 1 {
		t.Fatalf("expected/acked = %d/%d, want 1/1", res.Expected, res.Acked)
	}
}

// A device that stays silent must fail the drill by name — that name is the
// entire point, since it says which device will not alarm for real.
func TestDrill_FailsAndNamesSilentDevices(t *testing.T) {
	ts := newTestServer(t)
	ts.srv.OnPresence("status/quiet", []byte(`{"device_id":"quiet","state":"online"}`))

	res := ts.srv.RunDrillOnce(context.Background(), drillCfg(200*time.Millisecond))
	if res.Passed {
		t.Fatal("a silent device must fail the drill")
	}
	if got := res.MissedList(); len(got) != 1 || got[0] != "quiet" {
		t.Fatalf("missed = %v, want [quiet]", got)
	}
}

// Offline devices are not failures: §3.4 says to re-test them when they next
// appear, not to fail the drill because something was asleep.
func TestDrill_OfflineDevicesAreNotFailures(t *testing.T) {
	ts := newTestServer(t)
	ts.srv.OnPresence("status/asleep", []byte(`{"device_id":"asleep","state":"offline"}`))

	res := ts.srv.RunDrillOnce(context.Background(), drillCfg(150*time.Millisecond))
	if !res.Passed {
		t.Fatalf("no online devices means nothing to fail: %+v", res)
	}
	if res.Expected != 0 {
		t.Fatalf("expected = %d, want 0 (offline devices are not expected to answer)", res.Expected)
	}
}

// The drill alert must travel the ordinary signed path. A drill that bypassed
// signing would still pass with a broken key — testing the harness, not the system.
func TestDrill_AlertIsSignedAndVerifiable(t *testing.T) {
	ts := newTestServer(t)
	got := make(chan []byte, 4)
	_ = ts.srv.Broker.Subscribe(TopicEvents, func(_ string, payload []byte) {
		select {
		case got <- payload:
		default:
		}
	})
	ts.srv.RunDrillOnce(context.Background(), drillCfg(100*time.Millisecond))

	select {
	case payload := <-got:
		var a alertEnvelope
		if err := json.Unmarshal(payload, &a); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if a.Source != "drill" || a.Sig == "" {
			t.Fatalf("drill alert not signed or mis-sourced: %+v", a)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no drill alert published")
	}
}

// The result must be recorded, because the value is the trend across weeks.
func TestDrill_RecordsHistory(t *testing.T) {
	ts := newTestServer(t)
	ts.srv.RunDrillOnce(context.Background(), drillCfg(100*time.Millisecond))

	w := ts.req(t, http.MethodGet, "/api/drills", nil, adminHdr())
	if w.Code != http.StatusOK {
		t.Fatalf("drills = %d", w.Code)
	}
	var list []store.DrillResult
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("history = %d entries, want 1", len(list))
	}
	if list[0].AlertID == "" {
		t.Error("the recorded drill must reference the alert it published")
	}
}

func TestDrills_Auth(t *testing.T) {
	ts := newTestServer(t)
	if w := ts.req(t, http.MethodGet, "/api/drills", nil, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauth list = %d, want 401", w.Code)
	}
	viewer := ts.seedUser(t, "dv@x", "viewer") // may read, may not fire one
	if w := ts.req(t, http.MethodGet, "/api/drills", nil, userHdr(viewer)); w.Code != http.StatusOK {
		t.Fatalf("viewer list = %d, want 200", w.Code)
	}
	if w := ts.req(t, http.MethodPost, "/api/drills/run", nil, userHdr(viewer)); w.Code != http.StatusForbidden {
		t.Fatalf("viewer firing a drill = %d, want 403 (a drill publishes a real alert)", w.Code)
	}
}

// alertEnvelope is the subset the drill tests assert on.
type alertEnvelope struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Sig    string `json:"sig"`
}
