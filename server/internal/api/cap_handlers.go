package api

import (
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/KazuhaHub/AlertHub/server/internal/alert"
	"github.com/KazuhaHub/AlertHub/server/internal/cap"
	"github.com/KazuhaHub/AlertHub/server/internal/metrics"
	"github.com/KazuhaHub/AlertHub/server/internal/store"
)

// oneline strips CR/LF so CAP-sourced text is safe for the signed canonical form
// (SPEC §3.2 rule 7 forbids newlines in title/body/action).
func oneline(s string) string {
	return strings.TrimSpace(strings.NewReplacer("\n", " ", "\r", " ", "\t", " ").Replace(s))
}

// POST /api/cap — ingest a CAP 1.2 XML alert (scope alerts:ingest). The standard
// interop entry point for "other programs / emergency systems can call".
func (s *Server) handleCAPIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	doc, err := cap.Parse(body)
	if err != nil {
		metrics.CapIngest.WithLabelValues("error").Inc()
		http.Error(w, "invalid CAP XML: "+err.Error(), http.StatusBadRequest)
		return
	}
	m := doc.MapToAlert(time.Now())
	if m.MsgType == "Cancel" {
		s.handleCAPCancel(w, r, doc)
		return
	}
	// CAP Update supersedes what it references (CAP 1.2 §3.2.1). Re-issuing under
	// the REFERENCED alert's id — rather than publishing a second, unrelated
	// alert — is what makes it a supersede: clients keep one alert that updates in
	// place, and only re-alarm if the Update raised the severity (SPEC §5.2).
	supersedes := ""
	if m.MsgType == "Update" {
		if refs := cap.ParseReferences(doc.References); len(refs) > 0 {
			supersedes = cap.AlertID(refs[0].Sender, refs[0].Identifier)
		}
	}
	m.Title, m.Body, m.Action = oneline(m.Title), oneline(m.Body), oneline(m.Action)
	if err := alert.ValidateInput(m.Severity, m.Category, m.Title, m.Body, m.Action, "cap"); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a := &alert.Alert{
		SchemaVersion: alert.SchemaVersion,
		// Deterministic id from (sender, identifier) so a later CAP Cancel can recall
		// it (see cap.AlertID). An Update re-using the same identifier maps to the same
		// id → clients dedup/renew rather than double-alarm.
		// An Update takes over the referenced alert's id; anything else is keyed on
		// its own (sender, identifier).
		ID:       firstNonEmptyStr(supersedes, cap.AlertID(doc.Sender, doc.Identifier)),
		Type:     "alert",
		Category: m.Category,
		Severity: m.Severity,
		Title:    m.Title,
		Body:     m.Body,
		Action:   m.Action,
		Source:   "cap",
		IssuedAt: time.Now().Unix(),
		TTL:      m.TTL,
		Nonce:    alert.NewNonce(),
	}
	org := s.orgFor(r)
	if err := s.PublishAlert(a, org); err != nil {
		http.Error(w, "publish failed", http.StatusBadGateway)
		return
	}
	detail := "CAP ingest from " + doc.Sender + " " + doc.Identifier
	if supersedes != "" {
		detail = "CAP Update superseding " + supersedes
	}
	s.audit(r, org, AuditAlertPublish, "alert", a.ID, detail)
	metrics.CapIngest.WithLabelValues("ok").Inc()
	writeJSON(w, map[string]any{
		"id": a.ID, "severity": a.Severity, "category": a.Category,
		"test": m.IsTest, "supersedes": supersedes,
	})
}

// handleCAPCancel recalls the alert(s) a CAP Cancel references. Each CAP
// <references> entry is a (sender, identifier) that we map back — via the same
// deterministic cap.AlertID — to the id we published, then recall with the existing
// signed-cancel path (SPEC §5.1).
func (s *Server) handleCAPCancel(w http.ResponseWriter, r *http.Request, doc *cap.Document) {
	refs := cap.ParseReferences(doc.References)
	if len(refs) == 0 {
		metrics.CapIngest.WithLabelValues("error").Inc()
		http.Error(w, "CAP Cancel requires <references> to the alert(s) being cancelled", http.StatusBadRequest)
		return
	}
	org := s.orgFor(r)
	cancelled := make([]string, 0, len(refs))
	for _, ref := range refs {
		id := cap.AlertID(ref.Sender, ref.Identifier)
		if _, err := s.CancelByID(id, "cap", org); err != nil {
			http.Error(w, "cancel failed", http.StatusBadGateway)
			return
		}
		s.audit(r, org, AuditAlertCancel, "alert", id, "CAP Cancel referencing "+ref.Sender+" "+ref.Identifier)
		cancelled = append(cancelled, id)
	}
	metrics.CapIngest.WithLabelValues("cancel").Inc()
	writeJSON(w, map[string]any{"cancelled": cancelled})
}

// firstNonEmptyStr returns the first non-empty argument.
func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// --- outbound CAP -----------------------------------------------------------

// capSender identifies this instance in emitted CAP. A consumer dedupes on
// (sender, identifier), so this must be stable across restarts — hence config,
// not something derived from the request Host.
func (s *Server) capSender() string {
	if s.CAPSender != "" {
		return s.CAPSender
	}
	return "alerthub"
}

// GET /api/cap/alert?id=<alertID> — one alert as CAP 1.2 XML.
func (s *Server) handleCAPOut(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	org := s.orgFor(r)
	var found *alert.Alert
	err := s.inOrg(r.Context(), org, func(st *store.Store) error {
		envs, e := st.History(org, 200)
		if e != nil {
			return e
		}
		for _, raw := range envs {
			var a alert.Alert
			if json.Unmarshal(raw, &a) == nil && a.ID == id {
				found = &a
				return nil
			}
		}
		return nil
	})
	if err != nil {
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	if found == nil {
		http.NotFound(w, r)
		return
	}
	out, err := cap.ToXML(found, s.capSender())
	if err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/cap+xml; charset=utf-8")
	w.Header().Set("Cache-Control", cacheNoStore)
	_, _ = w.Write(out)
}

// GET /api/cap/feed — recent alerts as a CAP feed.
//
// Emitted as an Atom feed of CAP documents rather than concatenated <alert>
// elements: CAP has no multi-alert container, and consumers expect to poll a
// feed. Each entry carries the alert's own CAP document inline.
func (s *Server) handleCAPFeed(w http.ResponseWriter, r *http.Request) {
	org := s.orgFor(r)
	var envs []json.RawMessage
	err := s.inOrg(r.Context(), org, func(st *store.Store) error {
		var e error
		envs, e = st.History(org, 50)
		return e
	})
	if err != nil {
		http.Error(w, "feed failed", http.StatusInternalServerError)
		return
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<feed xmlns="http://www.w3.org/2005/Atom">` + "\n")
	b.WriteString("  <title>AlertHub CAP feed</title>\n")
	b.WriteString("  <id>urn:alerthub:" + xmlEscape(s.capSender()) + "</id>\n")
	b.WriteString("  <updated>" + time.Now().UTC().Format(time.RFC3339) + "</updated>\n")
	for _, raw := range envs {
		var a alert.Alert
		if json.Unmarshal(raw, &a) != nil {
			continue
		}
		doc, err := cap.ToXML(&a, s.capSender())
		if err != nil {
			continue
		}
		// Strip the XML declaration: it is illegal inside a document.
		inner := strings.TrimPrefix(string(doc), xml.Header)
		b.WriteString("  <entry>\n    <id>urn:alerthub:alert:" + xmlEscape(a.ID) + "</id>\n")
		b.WriteString("    <title>" + xmlEscape(a.Title) + "</title>\n")
		b.WriteString("    <updated>" + time.Unix(a.IssuedAt, 0).UTC().Format(time.RFC3339) + "</updated>\n")
		b.WriteString("    <content type=\"application/cap+xml\">\n" + inner + "\n    </content>\n  </entry>\n")
	}
	b.WriteString("</feed>\n")

	w.Header().Set("Content-Type", "application/atom+xml; charset=utf-8")
	w.Header().Set("Cache-Control", cacheNoStore)
	_, _ = w.Write([]byte(b.String()))
}

func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
