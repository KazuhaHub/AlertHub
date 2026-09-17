// Package cap parses OASIS CAP 1.2 alerts and maps them to AlertHub's envelope
// (ARCHITECTURE §7). CAP is the interop standard every serious emergency system
// speaks, so the public "other programs can call" API accepts it.
package cap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"strings"
	"time"

	"github.com/KazuhaHub/AlertHub/server/internal/alert"
)

// Document is the subset of CAP 1.2 we consume (XML, default namespace matched by
// local name). alert → info(+area). We use the first info block.
type Document struct {
	XMLName    xml.Name `xml:"alert"`
	Identifier string   `xml:"identifier"`
	Sender     string   `xml:"sender"`
	Sent       string   `xml:"sent"`
	Status     string   `xml:"status"`  // Actual | Exercise | System | Test | Draft
	MsgType    string   `xml:"msgType"` // Alert | Update | Cancel | Ack | Error
	Scope      string   `xml:"scope"`
	References string   `xml:"references"`
	Info       []Info   `xml:"info"`
}

type Info struct {
	Language     string `xml:"language"`
	Category     string `xml:"category"` // Geo|Met|Safety|Security|Rescue|Fire|Health|Env|Transport|Infra|CBRNE|Other
	Event        string `xml:"event"`
	ResponseType string `xml:"responseType"` // Shelter|Evacuate|Prepare|Execute|Avoid|Monitor|Assess|AllClear|None
	Urgency      string `xml:"urgency"`      // Immediate|Expected|Future|Past|Unknown
	Severity     string `xml:"severity"`     // Extreme|Severe|Moderate|Minor|Unknown
	Certainty    string `xml:"certainty"`    // Observed|Likely|Possible|Unlikely|Unknown
	Headline     string `xml:"headline"`
	Description  string `xml:"description"`
	Instruction  string `xml:"instruction"`
	Expires      string `xml:"expires"`
	Onset        string `xml:"onset"`
}

// Mapped is the normalized result the API turns into an alert.Alert.
type Mapped struct {
	Identifier string
	MsgType    string // Alert|Update|Cancel
	IsTest     bool   // status != Actual → drill/test, must NOT be a real alarm
	Category   string // AlertHub category
	Severity   string // AlertHub severity
	Title      string
	Body       string
	Action     string
	TTL        int64 // seconds
	References string
}

func Parse(b []byte) (*Document, error) {
	var d Document
	if err := xml.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// AlertID derives a deterministic, MQTT-topic-safe AlertHub id from a CAP message's
// (sender, identifier). Using a stable id — not a random UUID — is what lets a later
// CAP Cancel, which references the original (sender, identifier), recall the exact
// alert we published. Mirrors the EEW "eew-"+EventID pattern. 12 bytes = 96 bits of
// SHA-256 is ample against collision; the "cap-" prefix + hex keeps it topic-safe.
func AlertID(sender, identifier string) string {
	sum := sha256.Sum256([]byte(sender + "\x00" + identifier))
	return "cap-" + hex.EncodeToString(sum[:12])
}

// Reference is one parsed CAP <references> entry.
type Reference struct{ Sender, Identifier, Sent string }

// ParseReferences parses a CAP 1.2 <references> value: a whitespace-separated list
// of "sender,identifier,sent" triples (CAP 1.2 §3.2.1 — identifier/sender contain
// no spaces or commas, so this split is unambiguous). Entries without an identifier
// are dropped since they cannot be resolved to an alert.
func ParseReferences(s string) []Reference {
	var out []Reference
	for _, tok := range strings.Fields(s) {
		parts := strings.SplitN(tok, ",", 3)
		r := Reference{Sender: parts[0]}
		if len(parts) > 1 {
			r.Identifier = parts[1]
		}
		if len(parts) > 2 {
			r.Sent = parts[2]
		}
		if r.Identifier == "" {
			continue
		}
		out = append(out, r)
	}
	return out
}

var capCategory = map[string]string{
	"Fire": "fire", "Met": "weather", "Geo": "earthquake",
	"Security": "security", "Safety": "security", "Health": "system",
	"Infra": "system", "Env": "weather",
}

// MapToAlert collapses the CAP urgency/severity/certainty triple into AlertHub's
// single severity (ARCHITECTURE §7) and maps category/action.
func (d *Document) MapToAlert(now time.Time) Mapped {
	m := Mapped{
		Identifier: d.Identifier,
		MsgType:    firstNonEmpty(d.MsgType, "Alert"),
		IsTest:     d.Status != "" && d.Status != "Actual",
		References: d.References,
		Category:   "custom",
		Severity:   "notice",
	}
	if len(d.Info) == 0 {
		m.Title = firstNonEmpty(d.Identifier, "Alert")
		return m
	}
	i := d.Info[0]
	if c, ok := capCategory[i.Category]; ok {
		m.Category = c
	}
	m.Severity = collapseSeverity(i.Urgency, i.Severity, i.Certainty)
	if m.IsTest && rank(m.Severity) > rank("warning") {
		m.Severity = "warning" // never let a Test/Exercise fire a real fullscreen alarm
	}
	m.Title = firstNonEmpty(i.Headline, i.Event, "Alert")
	m.Body = strings.TrimSpace(i.Description)
	if i.Instruction != "" {
		if m.Body != "" {
			m.Body += "  "
		}
		m.Body += i.Instruction
	}
	m.Action = responseAction(i.ResponseType, i.Instruction)
	m.TTL = ttlFrom(i.Expires, now, m.Severity)
	return m
}

func collapseSeverity(urgency, severity, certainty string) string {
	if certainty == "Unlikely" {
		return "notice"
	}
	immediate := urgency == "Immediate"
	switch {
	case immediate && (severity == "Extreme" || severity == "Severe") && (certainty == "Observed" || certainty == "Likely"):
		return "emergency"
	case immediate && (severity == "Extreme" || severity == "Severe"):
		return "critical"
	case immediate && severity == "Moderate":
		return "critical"
	case urgency == "Expected" || urgency == "Future" || urgency == "":
		return "notice"
	case severity == "Moderate":
		return "warning"
	default:
		return "warning"
	}
}

func responseAction(rt, instruction string) string {
	switch rt {
	case "Shelter":
		return "就地避险 / Shelter in place"
	case "Evacuate":
		return "立即撤离 / Evacuate now"
	case "Execute":
		return "执行预案 / Execute the plan"
	case "Prepare":
		return "做好准备 / Prepare"
	case "Avoid":
		return "避开危险区域 / Avoid the area"
	case "AllClear":
		return "警报解除 / All clear"
	case "Monitor", "Assess":
		return "持续关注 / Monitor"
	}
	return strings.TrimSpace(instruction)
}

func ttlFrom(expires string, now time.Time, severity string) int64 {
	if expires != "" {
		if t, err := time.Parse(time.RFC3339, expires); err == nil {
			if d := int64(t.Sub(now).Seconds()); d > 0 {
				return d
			}
		}
	}
	switch severity {
	case "emergency", "critical":
		return 120
	default:
		return 600
	}
}

func rank(s string) int {
	return map[string]int{"notice": 0, "warning": 1, "critical": 2, "emergency": 3}[s]
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// --- outbound: AlertHub -> CAP 1.2 ------------------------------------------
//
// Emitting CAP is what makes AlertHub interoperable in the outbound direction:
// other emergency systems, aggregators and public feeds speak CAP, and a
// platform that can only consume it is a dead end.
//
// The mapping is the inverse of the ingest collapse, and it is lossy in a way
// worth being explicit about: ingest folds CAP's urgency × severity × certainty
// triple into one severity, so emitting has to invent a plausible triple back.
// We choose the triple that a CAP consumer would collapse to the SAME severity,
// which keeps a round-trip stable even though the original triple is gone.

type outAlert struct {
	XMLName    xml.Name `xml:"alert"`
	XMLNS      string   `xml:"xmlns,attr"`
	Identifier string   `xml:"identifier"`
	Sender     string   `xml:"sender"`
	Sent       string   `xml:"sent"`
	Status     string   `xml:"status"`
	MsgType    string   `xml:"msgType"`
	Scope      string   `xml:"scope"`
	References string   `xml:"references,omitempty"`
	Info       outInfo  `xml:"info"`
}

type outInfo struct {
	Language     string `xml:"language"`
	Category     string `xml:"category"`
	Event        string `xml:"event"`
	ResponseType string `xml:"responseType,omitempty"`
	Urgency      string `xml:"urgency"`
	Severity     string `xml:"severity"`
	Certainty    string `xml:"certainty"`
	Headline     string `xml:"headline"`
	Description  string `xml:"description,omitempty"`
	Instruction  string `xml:"instruction,omitempty"`
	Expires      string `xml:"expires,omitempty"`
}

// expandSeverity turns our single severity back into a CAP triple that collapses
// to the same value on the way in — see collapseSeverity, which this mirrors.
// Each triple below is chosen so collapseSeverity maps it back to the SAME
// severity — verified by a round-trip test, which is the only way to keep these
// two functions honest as either changes. Note the near misses: Severe+Likely
// would collapse to emergency (the first case accepts Observed OR Likely), and
// any Expected/Future urgency collapses to notice regardless of severity.
func expandSeverity(sev string) (urgency, severity, certainty string) {
	switch sev {
	case "emergency":
		return "Immediate", "Extreme", "Observed"
	case "critical":
		// Immediate + Severe, but NOT Observed/Likely — that combination is what
		// separates critical from emergency on the way in.
		return "Immediate", "Severe", "Possible"
	case "warning":
		// Must avoid Immediate (that path leads to critical/emergency) and avoid
		// Expected/Future (those collapse to notice). "Unknown" + Moderate lands
		// on warning.
		return "Unknown", "Moderate", "Likely"
	default: // notice
		return "Future", "Minor", "Possible"
	}
}

var outCategory = map[string]string{
	"earthquake": "Geo", "fire": "Fire", "weather": "Met",
	"security": "Security", "system": "Infra", "custom": "Other",
}

// ToXML renders one alert as CAP 1.2. sender identifies this AlertHub instance
// and must be a globally unique, stable string (CAP 1.2 §3.2.1) — a consumer
// dedupes on (sender, identifier), so a changing sender means duplicate alerts.
func ToXML(a *alert.Alert, sender string) ([]byte, error) {
	cat, ok := outCategory[a.Category]
	if !ok {
		cat = "Other"
	}
	msgType, refs := "Alert", ""
	if a.Type == "cancel" {
		msgType = "Cancel"
		// A CAP Cancel must say what it recalls, or a consumer cannot act on it.
		refs = sender + "," + a.Cancels + "," + time.Unix(a.IssuedAt, 0).UTC().Format(time.RFC3339)
	}
	urg, sev, cert := expandSeverity(a.Severity)

	doc := outAlert{
		XMLNS:      "urn:oasis:names:tc:emergency:cap:1.2",
		Identifier: a.ID,
		Sender:     sender,
		Sent:       time.Unix(a.IssuedAt, 0).UTC().Format(time.RFC3339),
		// "Actual" is the honest value for everything we publish EXCEPT drills,
		// which must never be mistaken for a real event by a downstream system.
		Status:     statusFor(a),
		MsgType:    msgType,
		Scope:      "Private", // this feed is authenticated, not a public broadcast
		References: refs,
		Info: outInfo{
			Language: "zh-CN", Category: cat, Event: a.Title,
			Urgency: urg, Severity: sev, Certainty: cert,
			Headline: a.Title, Description: a.Body, Instruction: a.Action,
			Expires: time.Unix(a.IssuedAt+a.TTL, 0).UTC().Format(time.RFC3339),
		},
	}
	out, err := xml.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), out...), nil
}

// statusFor keeps a drill labelled as one on the way out. Emitting a drill as
// "Actual" would let a downstream system escalate a test into a real response —
// the mirror image of the drill gate we apply on ingest.
func statusFor(a *alert.Alert) string {
	if a.Source == "drill" {
		return "Exercise"
	}
	return "Actual"
}
