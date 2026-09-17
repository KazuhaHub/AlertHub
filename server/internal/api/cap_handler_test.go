package api

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/AlertHub/server/internal/alert"
	"github.com/KazuhaHub/AlertHub/server/internal/cap"
)

const capAlertXML = `<?xml version="1.0"?>
<alert xmlns="urn:oasis:names:tc:emergency:cap:1.2">
  <identifier>EQ-100</identifier><sender>jma</sender><sent>2026-06-14T14:23:01+09:00</sent>
  <status>Actual</status><msgType>Alert</msgType><scope>Public</scope>
  <info><category>Geo</category><event>Earthquake</event>
  <urgency>Immediate</urgency><severity>Severe</severity><certainty>Observed</certainty>
  <headline>強い揺れ</headline></info>
</alert>`

// capPost sends a raw CAP XML body to /api/cap with the admin token.
func (ts *testServer) capPost(t *testing.T, xml string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRequest(http.MethodPost, "/api/cap", strings.NewReader(xml))
	rr.Header.Set("Authorization", "Bearer "+testAdminToken)
	w := httptest.NewRecorder()
	ts.handler.ServeHTTP(w, rr)
	return w
}

func TestCAPIngest_DeterministicID(t *testing.T) {
	ts := newTestServer(t)
	w := ts.capPost(t, capAlertXML)
	if w.Code != http.StatusOK {
		t.Fatalf("cap ingest = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if want := cap.AlertID("jma", "EQ-100"); got["id"] != want {
		t.Fatalf("ingest id = %v, want deterministic %s (so Cancel can recall it)", got["id"], want)
	}
}

// TestCAPCancel_RecallsReferencedAlert is the 501→implemented proof: a CAP Cancel
// that <references> a prior alert recalls the exact alert we published, and emits a
// signed cancel envelope for it.
func TestCAPCancel_RecallsReferencedAlert(t *testing.T) {
	ts := newTestServer(t)
	if w := ts.capPost(t, capAlertXML); w.Code != http.StatusOK {
		t.Fatalf("ingest = %d; body=%s", w.Code, w.Body.String())
	}

	cancelXML := `<alert xmlns="urn:oasis:names:tc:emergency:cap:1.2">
	  <identifier>EQ-100-C</identifier><sender>jma</sender><sent>2026-06-14T14:30:00+09:00</sent>
	  <status>Actual</status><msgType>Cancel</msgType><scope>Public</scope>
	  <references>jma,EQ-100,2026-06-14T14:23:01+09:00</references>
	  <info><category>Geo</category><event>Earthquake</event>
	  <urgency>Past</urgency><severity>Minor</severity><certainty>Observed</certainty>
	  <headline>解除</headline></info>
	</alert>`
	w := ts.capPost(t, cancelXML)
	if w.Code != http.StatusOK {
		t.Fatalf("cap cancel = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var got struct {
		Cancelled []string `json:"cancelled"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := cap.AlertID("jma", "EQ-100")
	if len(got.Cancelled) != 1 || got.Cancelled[0] != want {
		t.Fatalf("cancelled = %v, want [%s]", got.Cancelled, want)
	}

	// A signed cancel envelope for the original id must be recorded.
	hw := ts.req(t, http.MethodGet, "/api/history", nil, adminHdr())
	var hist []alert.Alert
	if err := json.Unmarshal(hw.Body.Bytes(), &hist); err != nil {
		t.Fatalf("decode history: %v", err)
	}
	found := false
	for _, a := range hist {
		if a.Type == "cancel" && a.Cancels == want {
			if !alert.Verify(&a, ts.pub) {
				t.Fatal("cancel envelope must be signed and verify")
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a signed cancel with cancels=%s in history; got %+v", want, hist)
	}
}

func TestCAPCancel_NoReferences400(t *testing.T) {
	ts := newTestServer(t)
	cancelXML := `<alert xmlns="urn:oasis:names:tc:emergency:cap:1.2">
	  <identifier>C-1</identifier><sender>jma</sender><status>Actual</status><msgType>Cancel</msgType>
	  <info><category>Geo</category><event>x</event></info></alert>`
	if w := ts.capPost(t, cancelXML); w.Code != http.StatusBadRequest {
		t.Fatalf("cancel without <references> = %d, want 400", w.Code)
	}
}

// TestCAPUpdate_SupersedesReferencedAlert: a CAP Update must take over the
// referenced alert's id rather than publishing a second, unrelated alert —
// otherwise a worsening situation shows up as two competing warnings.
func TestCAPUpdate_SupersedesReferencedAlert(t *testing.T) {
	ts := newTestServer(t)
	if w := ts.capPost(t, capAlertXML); w.Code != http.StatusOK {
		t.Fatalf("initial ingest = %d", w.Code)
	}
	original := cap.AlertID("jma", "EQ-100")

	updateXML := `<alert xmlns="urn:oasis:names:tc:emergency:cap:1.2">
	  <identifier>EQ-100-U</identifier><sender>jma</sender><sent>2026-06-14T14:25:00+09:00</sent>
	  <status>Actual</status><msgType>Update</msgType><scope>Public</scope>
	  <references>jma,EQ-100,2026-06-14T14:23:01+09:00</references>
	  <info><category>Geo</category><event>Earthquake</event>
	  <urgency>Immediate</urgency><severity>Extreme</severity><certainty>Observed</certainty>
	  <headline>震度上方修正</headline></info>
	</alert>`
	w := ts.capPost(t, updateXML)
	if w.Code != http.StatusOK {
		t.Fatalf("update = %d; body=%s", w.Code, w.Body.String())
	}
	var got struct {
		ID         string `json:"id"`
		Supersedes string `json:"supersedes"`
		Severity   string `json:"severity"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ID != original {
		t.Fatalf("Update published id %q, want the referenced alert's id %q", got.ID, original)
	}
	if got.Supersedes != original {
		t.Errorf("supersedes = %q, want %q", got.Supersedes, original)
	}
	if got.Severity != "emergency" {
		t.Errorf("severity = %q, want emergency (Immediate+Extreme+Observed)", got.Severity)
	}
}

// An Update with no <references> has nothing to supersede, so it stands on its
// own identifier rather than silently attaching to something arbitrary.
func TestCAPUpdate_WithoutReferencesIsItsOwnAlert(t *testing.T) {
	ts := newTestServer(t)
	updateXML := `<alert xmlns="urn:oasis:names:tc:emergency:cap:1.2">
	  <identifier>U-ALONE</identifier><sender>jma</sender><status>Actual</status><msgType>Update</msgType>
	  <info><category>Geo</category><event>x</event>
	  <urgency>Immediate</urgency><severity>Severe</severity><certainty>Observed</certainty>
	  <headline>h</headline></info></alert>`
	w := ts.capPost(t, updateXML)
	if w.Code != http.StatusOK {
		t.Fatalf("update = %d", w.Code)
	}
	var got struct {
		ID         string `json:"id"`
		Supersedes string `json:"supersedes"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.Supersedes != "" {
		t.Errorf("supersedes = %q, want empty", got.Supersedes)
	}
	if got.ID != cap.AlertID("jma", "U-ALONE") {
		t.Errorf("id = %q, want its own deterministic id", got.ID)
	}
}

// TestRenewAlert_SameIdFreshNonce pins the mechanic §5.2 depends on: the id is
// preserved so clients recognise it, but issued_at and nonce are fresh — a
// re-used nonce would make the renewal look like a replay and be dropped.
func TestRenewAlert_SameIdFreshNonce(t *testing.T) {
	ts := newTestServer(t)
	pw := ts.req(t, http.MethodPost, "/api/publish", validPublish(), adminHdr())
	var a alert.Alert
	_ = json.Unmarshal(pw.Body.Bytes(), &a)

	before := a
	renewed := a
	renewed.TTL = 600
	if err := ts.srv.RenewAlert(&renewed, ts.srv.DefaultOrgID); err != nil {
		t.Fatalf("renew: %v", err)
	}
	if renewed.ID != before.ID {
		t.Fatalf("renewal changed the id: %q -> %q", before.ID, renewed.ID)
	}
	if renewed.Nonce == before.Nonce {
		t.Fatal("renewal MUST carry a fresh nonce, or the client's replay check drops it")
	}
	if renewed.IssuedAt < before.IssuedAt {
		t.Error("renewal must not move issued_at backwards")
	}
	if !alert.Verify(&renewed, ts.pub) {
		t.Fatal("the renewed alert must be re-signed over its new canonical bytes")
	}
}

// --- outbound CAP endpoints --------------------------------------------------

func TestCAPOut_RendersPublishedAlert(t *testing.T) {
	ts := newTestServer(t)
	pw := ts.req(t, http.MethodPost, "/api/publish", validPublish(), adminHdr())
	var a alert.Alert
	_ = json.Unmarshal(pw.Body.Bytes(), &a)

	rr := httptest.NewRequest(http.MethodGet, "/api/cap/alert?id="+a.ID, nil)
	rr.Header.Set("Authorization", "Bearer "+testAdminToken)
	w := httptest.NewRecorder()
	ts.handler.ServeHTTP(w, rr)

	if w.Code != http.StatusOK {
		t.Fatalf("cap out = %d; body=%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "cap+xml") {
		t.Errorf("Content-Type = %q, want application/cap+xml", ct)
	}
	doc, err := cap.Parse(w.Body.Bytes())
	if err != nil {
		t.Fatalf("emitted document is not valid CAP: %v", err)
	}
	if doc.Identifier != a.ID {
		t.Errorf("identifier = %q, want the alert id %q", doc.Identifier, a.ID)
	}
	// The severity must survive the trip out and back.
	if got := doc.MapToAlert(time.Now()).Severity; got != a.Severity {
		t.Errorf("severity round-tripped to %q, want %q", got, a.Severity)
	}
}

func TestCAPOut_UnknownIDIs404(t *testing.T) {
	ts := newTestServer(t)
	rr := httptest.NewRequest(http.MethodGet, "/api/cap/alert?id=nope", nil)
	rr.Header.Set("Authorization", "Bearer "+testAdminToken)
	w := httptest.NewRecorder()
	ts.handler.ServeHTTP(w, rr)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown id = %d, want 404", w.Code)
	}
}

func TestCAPFeed_IsWellFormedAndAuthenticated(t *testing.T) {
	ts := newTestServer(t)
	_ = ts.req(t, http.MethodPost, "/api/publish", validPublish(), adminHdr())

	if w := ts.req(t, http.MethodGet, "/api/cap/feed", nil, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauth feed = %d, want 401 (this feed is not public)", w.Code)
	}
	rr := httptest.NewRequest(http.MethodGet, "/api/cap/feed", nil)
	rr.Header.Set("Authorization", "Bearer "+testAdminToken)
	w := httptest.NewRecorder()
	ts.handler.ServeHTTP(w, rr)
	if w.Code != http.StatusOK {
		t.Fatalf("feed = %d", w.Code)
	}
	// The whole feed must parse — a malformed entry would break every consumer.
	var probe struct{ XMLName xml.Name }
	if err := xml.Unmarshal(w.Body.Bytes(), &probe); err != nil {
		t.Fatalf("feed is not well-formed XML: %v", err)
	}
	if !strings.Contains(w.Body.String(), "cap+xml") {
		t.Error("feed entries should carry CAP documents")
	}
}
