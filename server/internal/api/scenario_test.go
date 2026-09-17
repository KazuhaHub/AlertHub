package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/KazuhaHub/AlertHub/server/internal/alert"
	"github.com/KazuhaHub/AlertHub/server/internal/scenario"
)

// The five canonical scenarios from §6.3 must all be present and each must carry
// a CAP responseType, or an emitted alert says something different downstream
// than it says to the person reading it.
func TestScenarios_CanonicalSetIsComplete(t *testing.T) {
	want := []string{"evacuate", "shelter", "lockdown", "dropcover", "allclear"}
	got := scenario.All()
	if len(got) != len(want) {
		t.Fatalf("%d scenarios, want %d", len(got), len(want))
	}
	for _, id := range want {
		sc, ok := scenario.Get(id)
		if !ok {
			t.Errorf("missing scenario %q", id)
			continue
		}
		if sc.ResponseType == "" {
			t.Errorf("%s has no CAP responseType", id)
		}
		if sc.Action == "" || sc.Title == "" {
			t.Errorf("%s must carry both a title and an instruction: %+v", id, sc)
		}
		// Every field lands in a signed canonical form, which forbids newlines.
		if err := alert.ValidateInput(sc.Severity, sc.Category, sc.Title, sc.Body, sc.Action, "scenario"); err != nil {
			t.Errorf("%s would be rejected at publish time: %v", id, err)
		}
	}
}

// An all-clear must not present as an emergency: making the relief itself
// another fullscreen alarm is how a system teaches people to dread it.
func TestScenarios_AllClearIsNotAnEmergency(t *testing.T) {
	sc, ok := scenario.Get("allclear")
	if !ok {
		t.Fatal("missing allclear")
	}
	if sc.Severity == "emergency" || sc.Severity == "critical" {
		t.Fatalf("all-clear severity = %q; it must not take over the screen", sc.Severity)
	}
	if sc.ResponseType != "AllClear" {
		t.Errorf("responseType = %q, want AllClear", sc.ResponseType)
	}
}

func TestScenarios_Endpoint(t *testing.T) {
	ts := newTestServer(t)
	if w := ts.req(t, http.MethodGet, "/api/scenarios", nil, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauth = %d, want 401", w.Code)
	}
	w := ts.req(t, http.MethodGet, "/api/scenarios", nil, adminHdr())
	if w.Code != http.StatusOK {
		t.Fatalf("scenarios = %d", w.Code)
	}
	var list []scenario.Scenario
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 5 {
		t.Fatalf("endpoint returned %d scenarios, want 5", len(list))
	}
}

// TestPublishScenario_UsesFixedWording is the reason this is a server endpoint:
// the instruction is fixed, so it cannot drift between clients.
func TestPublishScenario_UsesFixedWording(t *testing.T) {
	ts := newTestServer(t)
	w := ts.req(t, http.MethodPost, "/api/publish/scenario", map[string]string{"id": "evacuate"}, adminHdr())
	if w.Code != http.StatusOK {
		t.Fatalf("publish scenario = %d; body=%s", w.Code, w.Body.String())
	}
	var a alert.Alert
	if err := json.Unmarshal(w.Body.Bytes(), &a); err != nil {
		t.Fatalf("decode: %v", err)
	}
	sc, _ := scenario.Get("evacuate")
	if a.Title != sc.Title || a.Action != sc.Action {
		t.Fatalf("published wording drifted from the template: %+v", a)
	}
	if a.Source != "scenario:evacuate" {
		t.Errorf("source = %q, want scenario:evacuate so the trail says which template fired", a.Source)
	}
	if !alert.Verify(&a, ts.pub) {
		t.Error("a scenario alert must be signed like any other")
	}
}

// A caller may add context but must not be able to rewrite the instruction.
func TestPublishScenario_NoteAppendsWithoutReplacing(t *testing.T) {
	ts := newTestServer(t)
	w := ts.req(t, http.MethodPost, "/api/publish/scenario",
		map[string]string{"id": "shelter", "note": "台风 12 号"}, adminHdr())
	if w.Code != http.StatusOK {
		t.Fatalf("= %d", w.Code)
	}
	var a alert.Alert
	_ = json.Unmarshal(w.Body.Bytes(), &a)
	sc, _ := scenario.Get("shelter")
	if !strings.Contains(a.Body, sc.Body) {
		t.Error("the template body must survive the note")
	}
	if !strings.Contains(a.Body, "台风 12 号") {
		t.Error("the note should be appended")
	}
	if a.Action != sc.Action {
		t.Errorf("the instruction must not be overridable: %q", a.Action)
	}
}

// A note containing newlines must not be able to break the signed field framing.
func TestPublishScenario_NoteCannotBreakCanonicalFraming(t *testing.T) {
	ts := newTestServer(t)
	w := ts.req(t, http.MethodPost, "/api/publish/scenario",
		map[string]string{"id": "lockdown", "note": "line1\nline2\rline3"}, adminHdr())
	if w.Code != http.StatusOK {
		t.Fatalf("= %d; body=%s", w.Code, w.Body.String())
	}
	var a alert.Alert
	_ = json.Unmarshal(w.Body.Bytes(), &a)
	if strings.ContainsAny(a.Body, "\n\r") {
		t.Fatal("SECURITY: newlines survived into a signed field, which breaks canonical framing")
	}
}

func TestPublishScenario_UnknownIs404(t *testing.T) {
	ts := newTestServer(t)
	if w := ts.req(t, http.MethodPost, "/api/publish/scenario",
		map[string]string{"id": "nope"}, adminHdr()); w.Code != http.StatusNotFound {
		t.Fatalf("unknown scenario = %d, want 404", w.Code)
	}
}

func TestPublishScenario_RequiresPublishPerm(t *testing.T) {
	ts := newTestServer(t)
	viewer := ts.seedUser(t, "sv@x", "viewer")
	if w := ts.req(t, http.MethodPost, "/api/publish/scenario",
		map[string]string{"id": "evacuate"}, userHdr(viewer)); w.Code != http.StatusForbidden {
		t.Fatalf("viewer firing a scenario = %d, want 403", w.Code)
	}
}
