package api

// Collecting acknowledgements (SPEC §5.3). Clients have always published these;
// until now nothing subscribed, so the "who has confirmed" roster the spec
// describes did not exist. This closes that gap.

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/KazuhaHub/AlertHub/server/internal/store"
)

// TopicAckFilter matches every per-device ack: alerts/<alertID>/ack/<deviceID>.
const TopicAckFilter = "alerts/+/ack/#"

// OnAck handles one retained ack message from the broker.
//
// The device id is taken from the TOPIC, not from the payload: the broker ACL
// only lets a device write alerts/+/ack/<its own id>, so the topic is the part an
// attacker cannot forge. A payload claiming to be someone else is ignored.
func (s *Server) OnAck(topic string, payload []byte) {
	parts := strings.Split(topic, "/")
	// alerts / <alertID> / ack / <deviceID>
	if len(parts) != 4 || parts[0] != "alerts" || parts[2] != "ack" {
		return
	}
	alertID, deviceID := parts[1], parts[3]
	if alertID == "" || deviceID == "" {
		return
	}
	if len(payload) == 0 {
		return // cleared retained ack
	}
	var a store.Ack
	if err := json.Unmarshal(payload, &a); err != nil {
		slog.Debug("ack payload unparseable, using topic only", "topic", topic)
	}
	// Topic wins over payload for identity — see above.
	a.AlertID, a.DeviceID = alertID, deviceID

	// Acks are scoped to the default org because the device plane is still
	// single-tenant (devices have no org). RFC 0001 is where that gets fixed;
	// until then this is the honest attribution.
	if err := s.Store.RecordAck(s.DefaultOrgID, a); err != nil {
		slog.Error("record ack failed", "alert_id", alertID, "device_id", deviceID, "err", err)
		return
	}
	slog.Info("alert acknowledged", "alert_id", alertID, "device_id", deviceID)
}

type ackRoster struct {
	AlertID string      `json:"alert_id"`
	Acked   []store.Ack `json:"acked"`
	// Online is the device roster at query time, so a caller can see who has NOT
	// acknowledged — the number that actually matters during an incident.
	Online   []string `json:"online"`
	Pending  []string `json:"pending"`
	AckCount int      `json:"ack_count"`
}

// GET /api/alerts/acks?id=<alertID> — who confirmed, and who has not.
func (s *Server) handleAcks(w http.ResponseWriter, r *http.Request) {
	alertID := r.URL.Query().Get("id")
	if alertID == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	org := s.orgFor(r)
	acked, err := s.Store.ListAcks(org, alertID)
	if err != nil {
		http.Error(w, "ack lookup failed", http.StatusInternalServerError)
		return
	}
	ackedSet := map[string]bool{}
	for _, a := range acked {
		ackedSet[a.DeviceID] = true
	}
	// "Who is missing" is the operationally useful half, so compute it here
	// rather than making every caller join these two lists themselves.
	online, pending := []string{}, []string{}
	s.presenceMu.Lock()
	for id, p := range s.presence {
		if p.State != "online" {
			continue
		}
		online = append(online, id)
		if !ackedSet[id] {
			pending = append(pending, id)
		}
	}
	s.presenceMu.Unlock()

	writeJSON(w, ackRoster{
		AlertID: alertID, Acked: acked, Online: online,
		Pending: pending, AckCount: len(acked),
	})
}
