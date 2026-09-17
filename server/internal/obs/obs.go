// Package obs sets up process-wide observability: structured logging and the
// build-identity metric.
//
// Logging is JSON by default because these logs are meant to be shipped — the
// threat model in SECURITY.md and ARCHITECTURE §8 both assume a SIEM is reading
// them, and free-form text is not something a SIEM can alert on.
package obs

import (
	"log"
	"log/slog"
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Build identity. version/commit are injected at link time:
//
//	go build -ldflags "-X github.com/KazuhaHub/AlertHub/server/internal/obs.version=v1.2.3"
//
// A self-hosted product has to be able to answer "what are you running?" — from
// a log line, from /readyz, and from Prometheus.
var (
	version = "dev"
	commit  = ""
)

// Version returns the build version ("dev" for an unstamped build).
func Version() string { return version }

// Commit returns the build commit, falling back to the VCS stamp the Go
// toolchain embeds automatically when the tree is a git checkout.
func Commit() string {
	if commit != "" {
		return commit
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				if len(s.Value) > 12 {
					return s.Value[:12]
				}
				return s.Value
			}
		}
	}
	return "unknown"
}

// buildInfo follows the Prometheus convention: a constant-1 gauge whose labels
// carry the identity, so dashboards can join on it and alerts can spot a fleet
// running mixed versions.
var buildInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "alerthub_build_info",
	Help: "Build identity of the running binary (always 1).",
}, []string{"version", "commit", "go"})

// Setup installs the JSON (or text) structured logger as the process default and
// records the build-identity metric. Because it calls slog.SetDefault, the
// standard log package is routed through the same handler, so existing
// log.Printf call sites become structured records for free.
func Setup(format, level string) *slog.Logger {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn", "warning":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lv}

	var h slog.Handler
	if strings.EqualFold(format, "text") {
		h = slog.NewTextHandler(os.Stderr, opts)
	} else {
		h = slog.NewJSONHandler(os.Stderr, opts)
	}
	// "app_version", not "version": mochi-mqtt logs its own "version" attr, and a
	// colliding key produces a duplicate-key JSON record that some log pipelines
	// reject outright.
	logger := slog.New(h).With(
		slog.String("service", "alerthub"),
		slog.String("app_version", Version()),
	)
	slog.SetDefault(logger)
	// Drop the standard logger's own timestamp/prefix: slog stamps every record,
	// and a doubled timestamp inside the JSON "msg" is just noise.
	log.SetFlags(0)
	log.SetPrefix("")

	buildInfo.WithLabelValues(Version(), Commit(), runtime.Version()).Set(1)
	return logger
}
