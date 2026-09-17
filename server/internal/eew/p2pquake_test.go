package eew_test

import (
	"sync"
	"testing"

	"github.com/KazuhaHub/AlertHub/server/internal/eew"
)

const p2pEEW = `{
  "code":556,
  "issue":{"eventId":"20260814230000","serial":"3","type":"Detail"},
  "earthquake":{"hypocenter":{"name":"石川県能登地方","magnitude":6.4},"maxScale":55},
  "cancelled":false,"test":false
}`

func TestMapP2PQuake_Emergency(t *testing.T) {
	ev, ok := eew.MapP2PQuake([]byte(p2pEEW))
	if !ok {
		t.Fatal("a code-556 frame must map")
	}
	// maxScale 55 = 震度6弱 -> emergency (SPEC-SAFETY §6)
	if ev.Severity != "emergency" {
		t.Errorf("severity = %q, want emergency for maxScale 55 (6弱)", ev.Severity)
	}
	if ev.EventID != "20260814230000" || ev.Serial != 3 {
		t.Errorf("event id/serial = %q/%d", ev.EventID, ev.Serial)
	}
	if ev.Title == "" || ev.Body == "" || ev.Action == "" {
		t.Errorf("event is missing display text: %+v", ev)
	}
}

// Both relays must collapse an intensity to the SAME severity, otherwise which
// relay reported first would change how loudly the same quake alarms.
func TestP2PQuake_SeverityMatchesWolfx(t *testing.T) {
	cases := []struct {
		scale int
		want  string
	}{
		{70, "emergency"}, {60, "emergency"}, {55, "emergency"},
		{50, "critical"}, {45, "critical"}, {40, "critical"},
		{30, "warning"}, {10, "warning"},
	}
	for _, c := range cases {
		msg := `{"code":556,"issue":{"eventId":"x","serial":"1"},"earthquake":{"hypocenter":{"name":"n"},"maxScale":` +
			itoa(c.scale) + `}}`
		ev, ok := eew.MapP2PQuake([]byte(msg))
		if !ok {
			t.Fatalf("scale %d did not map", c.scale)
		}
		if ev.Severity != c.want {
			t.Errorf("maxScale %d -> %q, want %q", c.scale, ev.Severity, c.want)
		}
	}
}

func TestMapP2PQuake_IgnoresOtherChannels(t *testing.T) {
	// 551 is a quake report, not an EEW; the socket carries plenty of it.
	if _, ok := eew.MapP2PQuake([]byte(`{"code":551,"issue":{"eventId":"x"}}`)); ok {
		t.Error("non-556 frames must be ignored")
	}
	if _, ok := eew.MapP2PQuake([]byte(`not json`)); ok {
		t.Error("garbage must be ignored")
	}
	if _, ok := eew.MapP2PQuake([]byte(`{"code":556,"issue":{"eventId":""}}`)); ok {
		t.Error("a frame with no event id must be ignored")
	}
}

// A drill must never fire a real fullscreen alarm, on either source.
func TestMapP2PQuake_TestFrameIsCapped(t *testing.T) {
	msg := `{"code":556,"issue":{"eventId":"t1","serial":"1"},
	         "earthquake":{"hypocenter":{"name":"n"},"maxScale":70},"test":true}`
	ev, ok := eew.MapP2PQuake([]byte(msg))
	if !ok {
		t.Fatal("did not map")
	}
	if !ev.IsTest {
		t.Error("test frame must be flagged")
	}
	if ev.Severity == "emergency" || ev.Severity == "critical" {
		t.Errorf("a test must not map to %q", ev.Severity)
	}
}

func TestMapP2PQuake_Cancel(t *testing.T) {
	msg := `{"code":556,"issue":{"eventId":"c1","serial":"9"},
	         "earthquake":{"hypocenter":{"name":"n"},"maxScale":45},"cancelled":true}`
	ev, ok := eew.MapP2PQuake([]byte(msg))
	if !ok || !ev.IsCancel {
		t.Fatalf("cancel frame = %+v, ok=%v", ev, ok)
	}
}

// --- the shared deduper: what makes two sources redundancy, not noise --------

func TestDeduper_OneQuakeReportedByBothSourcesFiresOnce(t *testing.T) {
	d := eew.NewDeduper()
	if !d.FirstSeen("evt-1") {
		t.Fatal("the first report must pass")
	}
	if d.FirstSeen("evt-1") {
		t.Fatal("the second relay reporting the SAME quake must be suppressed — otherwise dual-source double-alarms")
	}
	if !d.FirstSeen("evt-2") {
		t.Fatal("a different quake must pass")
	}
}

// After a cancel the event is forgotten, so a re-issued warning gets through.
func TestDeduper_ForgetAllowsReissue(t *testing.T) {
	d := eew.NewDeduper()
	d.FirstSeen("evt-1")
	d.Forget("evt-1")
	if !d.FirstSeen("evt-1") {
		t.Fatal("after a cancel, a re-issued warning for the same event must be emitted again")
	}
}

// Two source goroutines hit this concurrently; exactly one must win.
func TestDeduper_ConcurrentFirstSeenElectsOneWinner(t *testing.T) {
	d := eew.NewDeduper()
	const n = 50
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if d.FirstSeen("same-quake") {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d goroutines claimed the same event; want exactly 1", wins)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// --- intensity upgrades ------------------------------------------------------

// TestDeduper_UpgradePassesThrough is the safety case: a quake first reported as
// 震度4 and revised to 6弱 must reach people again. Suppressing it would leave
// them acting on the wrong instruction.
func TestDeduper_UpgradePassesThrough(t *testing.T) {
	d := eew.NewDeduper()

	emit, upgrade := d.Emit("q1", "critical")
	if !emit || upgrade {
		t.Fatalf("first report: emit=%v upgrade=%v, want true/false", emit, upgrade)
	}
	emit, upgrade = d.Emit("q1", "emergency")
	if !emit || !upgrade {
		t.Fatalf("upward revision: emit=%v upgrade=%v, want true/true", emit, upgrade)
	}
}

// A repeat at the same severity, or a downgrade, must stay suppressed —
// re-alarming for no new information is how people learn to ignore alerts.
func TestDeduper_RepeatAndDowngradeSuppressed(t *testing.T) {
	d := eew.NewDeduper()
	d.Emit("q1", "emergency")

	if emit, _ := d.Emit("q1", "emergency"); emit {
		t.Error("a repeat at the same severity must be suppressed")
	}
	if emit, _ := d.Emit("q1", "critical"); emit {
		t.Error("a downgrade must be suppressed")
	}
	if emit, _ := d.Emit("q1", "warning"); emit {
		t.Error("a further downgrade must be suppressed")
	}
}

// After an upgrade, the new level becomes the bar: another report at that level
// is a repeat, and only a further rise gets through.
func TestDeduper_UpgradeRaisesTheBar(t *testing.T) {
	d := eew.NewDeduper()
	d.Emit("q1", "warning")
	d.Emit("q1", "critical")
	if emit, _ := d.Emit("q1", "critical"); emit {
		t.Error("repeat at the upgraded level must be suppressed")
	}
	if emit, up := d.Emit("q1", "emergency"); !emit || !up {
		t.Error("a further rise must still get through")
	}
}
