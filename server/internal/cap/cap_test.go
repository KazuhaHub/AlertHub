package cap_test

import (
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/AlertHub/server/internal/alert"
	"github.com/KazuhaHub/AlertHub/server/internal/cap"
)

const eqXML = `<?xml version="1.0"?>
<alert xmlns="urn:oasis:names:tc:emergency:cap:1.2">
  <identifier>EQ-001</identifier><sender>jma</sender><sent>2026-06-14T14:23:01+09:00</sent>
  <status>Actual</status><msgType>Alert</msgType><scope>Public</scope>
  <info>
    <category>Geo</category><event>Earthquake Early Warning</event>
    <responseType>Shelter</responseType>
    <urgency>Immediate</urgency><severity>Severe</severity><certainty>Observed</certainty>
    <headline>緊急地震速報</headline>
    <description>強い揺れに警戒してください。</description>
    <instruction>頭を守り、机の下へ。</instruction>
  </info>
</alert>`

func TestMapEarthquakeEmergency(t *testing.T) {
	d, err := cap.Parse([]byte(eqXML))
	if err != nil {
		t.Fatal(err)
	}
	m := d.MapToAlert(time.Now())
	if m.Category != "earthquake" {
		t.Errorf("category = %q, want earthquake", m.Category)
	}
	if m.Severity != "emergency" {
		t.Errorf("severity = %q, want emergency (Immediate+Severe+Observed)", m.Severity)
	}
	if m.Title != "緊急地震速報" {
		t.Errorf("title = %q", m.Title)
	}
	if m.Action == "" {
		t.Error("expected an action from responseType Shelter")
	}
	if m.IsTest {
		t.Error("status Actual must not be a test")
	}
	if m.TTL <= 0 {
		t.Errorf("ttl = %d, want >0", m.TTL)
	}
}

const testXML = `<alert xmlns="urn:oasis:names:tc:emergency:cap:1.2">
  <identifier>EX-1</identifier><status>Exercise</status><msgType>Alert</msgType>
  <info><category>Fire</category><event>Drill</event>
  <urgency>Immediate</urgency><severity>Extreme</severity><certainty>Observed</certainty>
  <headline>Fire drill</headline></info></alert>`

func TestExerciseNeverRealAlarm(t *testing.T) {
	d, _ := cap.Parse([]byte(testXML))
	m := d.MapToAlert(time.Now())
	if !m.IsTest {
		t.Error("Exercise status must be flagged IsTest")
	}
	if m.Severity == "emergency" || m.Severity == "critical" {
		t.Errorf("a Test/Exercise must not map to %q (no real fullscreen alarm)", m.Severity)
	}
	if m.Category != "fire" {
		t.Errorf("category = %q, want fire", m.Category)
	}
}

func TestAlertID_DeterministicAndTopicSafe(t *testing.T) {
	a := cap.AlertID("jma", "EQ-1")
	if a != cap.AlertID("jma", "EQ-1") {
		t.Fatal("AlertID must be deterministic for the same (sender, identifier)")
	}
	if cap.AlertID("jma", "EQ-2") == a {
		t.Fatal("different identifiers must yield different ids")
	}
	if cap.AlertID("other", "EQ-1") == a {
		t.Fatal("different senders must yield different ids")
	}
	if !strings.HasPrefix(a, "cap-") {
		t.Fatalf("id %q must carry the cap- prefix", a)
	}
	if strings.ContainsAny(a, "/+# ") { // MQTT wildcards / separators / spaces
		t.Fatalf("id %q must be MQTT-topic-safe", a)
	}
}

func TestParseReferences(t *testing.T) {
	refs := cap.ParseReferences(
		"jma,EQ-1,2026-06-14T14:23:01+09:00 jma,EQ-2,2026-06-14T14:24:00+09:00")
	if len(refs) != 2 {
		t.Fatalf("want 2 refs, got %d (%+v)", len(refs), refs)
	}
	if refs[0].Sender != "jma" || refs[0].Identifier != "EQ-1" || refs[0].Sent == "" {
		t.Fatalf("ref0 = %+v", refs[0])
	}
	if refs[1].Identifier != "EQ-2" {
		t.Fatalf("ref1 = %+v", refs[1])
	}
	if len(cap.ParseReferences("")) != 0 {
		t.Fatal("empty references => no entries")
	}
	if len(cap.ParseReferences("senderonly")) != 0 {
		t.Fatal("a token with no identifier must be dropped")
	}
}

// --- outbound CAP ------------------------------------------------------------

// TestToXML_RoundTripsSeverity is the property that matters: ingest collapses
// CAP's urgency × severity × certainty into one value, so emitting has to invent
// a triple back. It must be a triple that collapses to the SAME severity, or
// alerts drift every time they cross a system boundary.
func TestToXML_RoundTripsSeverity(t *testing.T) {
	for _, sev := range []string{"emergency", "critical", "warning", "notice"} {
		a := &alert.Alert{
			SchemaVersion: alert.SchemaVersion, ID: "x-" + sev, Type: "alert",
			Category: "fire", Severity: sev, Title: "t", Source: "panel",
			IssuedAt: 1765238400, TTL: 600,
		}
		xmlBytes, err := cap.ToXML(a, "alerthub-test")
		if err != nil {
			t.Fatalf("%s: ToXML: %v", sev, err)
		}
		doc, err := cap.Parse(xmlBytes)
		if err != nil {
			t.Fatalf("%s: emitted XML does not parse as CAP: %v", sev, err)
		}
		got := doc.MapToAlert(time.Unix(1765238400, 0))
		if got.Severity != sev {
			t.Errorf("%s round-tripped to %s — the emitted triple collapses differently", sev, got.Severity)
		}
		if got.Category != "fire" {
			t.Errorf("%s: category round-tripped to %q, want fire", sev, got.Category)
		}
	}
}

// A drill must not be emitted as Actual, or a downstream system could escalate a
// test into a real response — the mirror of the drill gate we apply on ingest.
func TestToXML_DrillIsNotActual(t *testing.T) {
	a := &alert.Alert{
		SchemaVersion: alert.SchemaVersion, ID: "d1", Type: "alert", Category: "system",
		Severity: "warning", Title: "drill", Source: "drill", IssuedAt: 1765238400, TTL: 600,
	}
	out, err := cap.ToXML(a, "alerthub-test")
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := cap.Parse(out)
	if doc.Status != "Exercise" {
		t.Fatalf("drill emitted with status %q, want Exercise", doc.Status)
	}
	if !doc.MapToAlert(time.Now()).IsTest {
		t.Error("a re-ingested drill must still be flagged as a test")
	}
}

// A Cancel must say what it recalls, or a consumer cannot act on it.
func TestToXML_CancelCarriesReferences(t *testing.T) {
	c := &alert.Alert{
		SchemaVersion: alert.SchemaVersion, ID: "c1", Type: "cancel", Category: "custom",
		Severity: "notice", Title: "解除", Cancels: "orig-1", IssuedAt: 1765238400, TTL: 120,
	}
	out, err := cap.ToXML(c, "alerthub-test")
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := cap.Parse(out)
	if doc.MsgType != "Cancel" {
		t.Fatalf("msgType = %q, want Cancel", doc.MsgType)
	}
	refs := cap.ParseReferences(doc.References)
	if len(refs) != 1 || refs[0].Identifier != "orig-1" {
		t.Fatalf("references = %+v, want one entry naming orig-1", refs)
	}
}

// Emitted XML must be well-formed even when the alert text contains characters
// that are special in XML.
func TestToXML_EscapesText(t *testing.T) {
	a := &alert.Alert{
		SchemaVersion: alert.SchemaVersion, ID: "e1", Type: "alert", Category: "fire",
		Severity: "critical", Title: `火灾 & <script>alert("x")</script>`,
		Body: "a > b", IssuedAt: 1765238400, TTL: 600,
	}
	out, err := cap.ToXML(a, "alerthub-test")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := cap.Parse(out)
	if err != nil {
		t.Fatalf("XML with special characters did not round-trip: %v", err)
	}
	if doc.Info[0].Headline != a.Title {
		t.Fatalf("headline = %q, want the original text back", doc.Info[0].Headline)
	}
}
