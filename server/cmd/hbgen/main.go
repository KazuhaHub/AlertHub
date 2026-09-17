// Command hbgen prints one signed heartbeat as JSON, using the SAME
// alert.SignHeartbeat the server uses and the same key directory.
//
// It exists so the cross-language conformance check can cover the heartbeat
// canonical form as well as the alert one. The real beat is published over MQTT,
// which the hermetic Node conformance script has no client for (the browser loads
// mqtt.js from a CDN), so this reproduces the signing half exactly. That is where
// the cross-language risk actually lives: Go's CanonicalHeartbeat and JS's
// canonicalHeartbeatBytes must agree byte for byte.
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
		fmt.Fprintf(os.Stderr, "hbgen: read key: %v\n", err)
		os.Exit(1)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		fmt.Fprintf(os.Stderr, "hbgen: bad key file\n")
		os.Exit(1)
	}
	hb := &alert.Heartbeat{
		SchemaVersion: alert.SchemaVersion,
		Type:          "heartbeat",
		Seq:           7,
		IssuedAt:      1765238400,
		Interval:      10,
		ActiveCount:   1,
		Health:        alert.HealthDegraded, // exercise a non-default value
	}
	alert.SignHeartbeat(hb, ed25519.PrivateKey(key))
	out, _ := json.Marshal(hb)
	fmt.Println(string(out))
}
