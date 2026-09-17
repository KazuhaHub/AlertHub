package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/KazuhaHub/AlertHub/server/internal/alert"
	"github.com/KazuhaHub/AlertHub/server/internal/scenario"
)

// GET /api/scenarios — the one-tap templates every client should offer.
func (s *Server) handleScenarios(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, scenario.All())
}

// POST /api/publish/scenario {id, body?} — fire a template.
//
// A separate endpoint rather than "fill the form client-side and POST /publish":
// the whole point of a scenario is that the wording is fixed and identical
// everywhere, and a client that assembles it locally can drift from the others.
// The caller may add context to the body; it cannot rewrite the instruction.
func (s *Server) handlePublishScenario(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID   string `json:"id"`
		Note string `json:"note"` // optional extra context appended to the body
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	sc, ok := scenario.Get(req.ID)
	if !ok {
		http.Error(w, "unknown scenario", http.StatusNotFound)
		return
	}
	body := sc.Body
	if note := oneline(req.Note); note != "" {
		body += "  " + note
	}
	if err := alert.ValidateInput(sc.Severity, sc.Category, sc.Title, body, sc.Action, "scenario"); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a := &alert.Alert{
		SchemaVersion: alert.SchemaVersion,
		ID:            alert.NewID(),
		Type:          "alert",
		Category:      sc.Category,
		Severity:      sc.Severity,
		Title:         sc.Title,
		Body:          body,
		Action:        sc.Action,
		Source:        "scenario:" + sc.ID,
		IssuedAt:      time.Now().Unix(),
		TTL:           sc.TTL,
		Nonce:         alert.NewNonce(),
	}
	org := s.orgFor(r)
	if err := s.PublishAlert(a, org); err != nil {
		http.Error(w, "publish failed", http.StatusBadGateway)
		return
	}
	s.audit(r, org, AuditAlertPublish, "alert", a.ID, "scenario "+sc.ID+": "+sc.Title)
	writeJSON(w, a)
}
