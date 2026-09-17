// Command gatefixtures emits a set of PROPERLY SIGNED envelopes that exercise the
// SPEC §5.2 accept-gate branches, so the cross-language conformance script can
// check the JS gate against real signatures.
//
// It exists because that classification (replay vs renewal vs escalation) lives
// only in web/verify.js — no Go test can reach it — and the client cannot forge
// the signatures needed to construct the cases itself.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/KazuhaHub/AlertHub/server/internal/alert"
)

func main() {
	dir := os.Getenv("ALERTHUB_KEY_DIR")
	if dir == "" {
		dir = "keys"
	}
	raw, err := os.ReadFile(filepath.Join(dir, "alerthub_ed25519.key"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "gatefixtures: read key: %v\n", err)
		os.Exit(1)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		fmt.Fprintln(os.Stderr, "gatefixtures: bad key file")
		os.Exit(1)
	}
	priv := ed25519.PrivateKey(key)

	// now is passed in so the fixtures sit inside the client's ±120s skew window.
	var now int64
	fmt.Sscanf(os.Getenv("ALERTHUB_NOW"), "%d", &now)
	if now == 0 {
		fmt.Fprintln(os.Stderr, "gatefixtures: set ALERTHUB_NOW to the current unix time")
		os.Exit(1)
	}

	mk := func(id, sev string, issuedAt int64) *alert.Alert {
		a := &alert.Alert{
			SchemaVersion: alert.SchemaVersion, ID: id, Type: "alert",
			Category: "system", Severity: sev, Title: "gate probe",
			Source: "panel", IssuedAt: issuedAt, TTL: 600, Nonce: alert.NewNonce(),
		}
		alert.Sign(a, priv)
		return a
	}

	const id = "gate-probe-fixed-id"
	base := mk(id, "warning", now)
	// Renewal: same id, newer issued_at, FRESH nonce, unchanged severity.
	renewal := mk(id, "warning", now+1)
	// Escalation: same id, newer still, severity raised.
	escalation := mk(id, "emergency", now+2)
	// Stale re-delivery: same id but older than what the client already stored.
	stale := mk(id, "warning", now-5)

	out, _ := json.Marshal(map[string]any{
		"base": base, "renewal": renewal, "escalation": escalation, "stale": stale,
	})
	fmt.Println(string(out))
}
