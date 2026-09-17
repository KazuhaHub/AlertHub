// Package api wires the HTTP publish/cancel/history/pubkey endpoints, owns the
// alerts/active replacement policy + TTL sweeper, and serves the web UI.
// See SPEC.md §5 (topology), §7 (API).
package api

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io/fs"
	"log"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/KazuhaHub/AlertHub/server/internal/alert"
	"github.com/KazuhaHub/AlertHub/server/internal/auth"
	"github.com/KazuhaHub/AlertHub/server/internal/broker"
	"github.com/KazuhaHub/AlertHub/server/internal/delivery"
	"github.com/KazuhaHub/AlertHub/server/internal/metrics"
	"github.com/KazuhaHub/AlertHub/server/internal/ntfy"
	"github.com/KazuhaHub/AlertHub/server/internal/obs"
	"github.com/KazuhaHub/AlertHub/server/internal/passkey"
	"github.com/KazuhaHub/AlertHub/server/internal/sso"
	"github.com/KazuhaHub/AlertHub/server/internal/store"
	"github.com/KazuhaHub/AlertHub/server/internal/twofa"
	"github.com/KazuhaHub/AlertHub/server/internal/webadmin"
)

const (
	TopicActive       = "alerts/active"    // retained snapshot of the current top alert
	TopicEvents       = "alerts/events"    // non-retained real-time feed (alerts + cancels)
	TopicHeartbeat    = "system/heartbeat" // retained signed liveness beacon (SPEC-SAFETY §3.1)
	MaxSkew           = 120                // seconds; mirrors SPEC §4, sent to clients via /pubkey
	HeartbeatInterval = 10                 // seconds between heartbeats
)

type Server struct {
	Broker    *broker.Broker
	Store     *store.Store
	Priv      ed25519.PrivateKey
	PubB64url string // base64url raw 32-byte public key currently used for SIGNING
	// PubB64urlExtra are additional keys clients should still ACCEPT (SPEC §8
	// rotation). Signing always uses PubB64url; these exist so a key can be
	// replaced without downtime — clients accept old and new during the overlap.
	PubB64urlExtra []string
	AdminToken     string
	WebDir         string

	// Browser-client bootstrap info served at /pubkey (SPEC §7/§8). The client
	// MQTT password is not a real secret in a browser — the trust anchor is the
	// signature and the ACL that forbids clients from writing alert channels.
	WSPort     string
	ClientUser string
	ClientPass string

	Ntfy     *ntfy.Publisher   // independent backup channel (SPEC-SAFETY §4)
	Delivery *delivery.Manager // durable outbox: webhook + email, at-least-once
	Auth     *auth.Service     // admin/human JWT auth (Passwall-style)
	Passkey  *passkey.Service  // WebAuthn/passkey (admin auth)
	TwoFA    *twofa.Service    // TOTP + recovery codes (admin auth)
	OIDC     *sso.OIDC         // OIDC single sign-on (admin auth)
	SAML     *sso.SAML         // SAML single sign-on (admin auth)

	// Feature flags reported by /api/sources. They record whether a channel was
	// configured, never the credential behind it.
	EEWEnabled         bool
	WatchdogConfigured bool
	SIEMConfigured     bool

	// CAPSender identifies this instance in EMITTED CAP. Consumers dedupe on
	// (sender, identifier), so it must be stable across restarts.
	CAPSender string

	OIDCDefaultRole string // role for JIT-provisioned SSO users
	DefaultOrgID    int64  // single-tenant active org (M1; per-request active org is M2)

	mu     sync.Mutex
	active *alert.Alert // current alerts/active snapshot (nil = none)
	// lastPublishErr is the most recent broker publish outcome, surfaced by
	// selfCheck() in the next heartbeat. Empty = the last publish succeeded.
	lastPublishErr string

	esc *escalator // SPEC-SAFETY §5 ladder state

	DrillCfg DrillConfig // SPEC-SAFETY §3.4 weekly drill

	presenceMu sync.Mutex
	presence   map[string]Presence // deviceId -> last presence (from status/#)
}

// Handler returns the full HTTP mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Per-IP limiter shared by the credential-verification endpoints, to slow
	// brute-force (10 attempts / minute / IP). Token-authenticated endpoints
	// (refresh, publish, …) are not limited — their secrets aren't guessable.
	authLimit := newRateLimiter(10, time.Minute)
	// Admin auth (Passwall-style; admin login only — device auth is separate).
	mux.HandleFunc("/api/auth/methods", s.handleAuthMethods)
	mux.HandleFunc("/api/auth/login", s.rateLimit(authLimit, s.handleLogin))
	mux.HandleFunc("/api/auth/refresh", s.handleRefresh)
	mux.HandleFunc("/api/auth/logout", s.handleLogout)
	mux.HandleFunc("/api/auth/me", s.requireRole(auth.RoleUser, s.handleMe))
	// Passkey / WebAuthn (admin auth).
	mux.HandleFunc("/api/auth/passkey/register/begin", s.requireRole(auth.RoleUser, s.handlePasskeyRegBegin))
	mux.HandleFunc("/api/auth/passkey/register/finish", s.requireRole(auth.RoleUser, s.handlePasskeyRegFinish))
	mux.HandleFunc("/api/auth/passkey/login/begin", s.handlePasskeyLoginBegin)
	mux.HandleFunc("/api/auth/passkey/login/finish", s.rateLimit(authLimit, s.handlePasskeyLoginFinish))
	mux.HandleFunc("/api/auth/passkey/list", s.requireRole(auth.RoleUser, s.handlePasskeyList))
	mux.HandleFunc("/api/auth/passkey/delete", s.requireRole(auth.RoleUser, s.handlePasskeyDelete))
	// TOTP / 2FA.
	mux.HandleFunc("/api/auth/2fa/verify", s.rateLimit(authLimit, s.handle2FAVerify)) // public: pending token + code
	mux.HandleFunc("/api/auth/2fa/status", s.requireRole(auth.RoleUser, s.handle2FAStatus))
	mux.HandleFunc("/api/auth/2fa/begin", s.requireRole(auth.RoleUser, s.handle2FABegin))
	mux.HandleFunc("/api/auth/2fa/enable", s.requireRole(auth.RoleUser, s.handle2FAEnable))
	mux.HandleFunc("/api/auth/2fa/disable", s.requireRole(auth.RoleUser, s.handle2FADisable))
	// OIDC SSO (public flow).
	mux.HandleFunc("/api/auth/oidc/login", s.handleOIDCLogin)
	mux.HandleFunc("/api/auth/oidc/callback", s.handleOIDCCallback)
	mux.HandleFunc("/api/auth/oidc/exchange", s.rateLimit(authLimit, s.handleOIDCExchange))
	// SAML SSO.
	mux.HandleFunc("/api/auth/saml/login", s.handleSAMLLogin)
	mux.HandleFunc("/api/auth/saml/acs", s.rateLimit(authLimit, s.handleSAMLACS))
	mux.HandleFunc("/api/auth/saml/metadata", s.handleSAMLMetadata)
	// CAP 1.2 ingest — the interop API for other programs/systems (service-account
	// API key with scope alerts:ingest, or admin).
	mux.HandleFunc("/api/cap", s.requireScope("alerts:ingest", s.handleCAPIngest))
	// Outbound CAP: let other systems consume our alerts in the standard format.
	mux.HandleFunc("/api/cap/alert", s.requirePerm(auth.PermAlertRead, s.handleCAPOut))
	mux.HandleFunc("/api/cap/feed", s.requirePerm(auth.PermAlertRead, s.handleCAPFeed))
	// Service-account (API key) management (RBAC: sa:manage).
	mux.HandleFunc("/api/admin/service-accounts", s.requirePerm(auth.PermSAManage, s.handleServiceAccounts))
	mux.HandleFunc("/api/admin/service-accounts/delete", s.requirePerm(auth.PermSAManage, s.handleServiceAccountDelete))
	// Alert ops (RBAC; static admin token still works for scripts).
	mux.HandleFunc("/api/publish", s.requirePerm(auth.PermAlertPublish, s.handlePublish))
	// One-tap scenario templates (SPEC-SAFETY §6.3): server-owned so every client
	// offers identical wording.
	mux.HandleFunc("/api/scenarios", s.requirePerm(auth.PermAlertRead, s.handleScenarios))
	mux.HandleFunc("/api/publish/scenario", s.requirePerm(auth.PermAlertPublish, s.handlePublishScenario))
	mux.HandleFunc("/api/cancel", s.requirePerm(auth.PermAlertCancel, s.handleCancel))
	mux.HandleFunc("/api/history", s.requirePerm(auth.PermAlertRead, s.handleHistory))
	mux.HandleFunc("/api/devices", s.requirePerm(auth.PermDeviceRead, s.handleDevices))
	// Who acknowledged an alert, and who is online but has not (SPEC §5.3).
	mux.HandleFunc("/api/alerts/acks", s.requirePerm(auth.PermAlertRead, s.handleAcks))
	// Live escalation ladder: which alerts are still unacknowledged, and by whom.
	mux.HandleFunc("/api/alerts/escalations", s.requirePerm(auth.PermAlertRead, s.handleEscalations))
	// Drill history + on-demand run (SPEC-SAFETY §3.4).
	mux.HandleFunc("/api/drills", s.requirePerm(auth.PermAlertRead, s.handleDrills))
	mux.HandleFunc("/api/drills/run", s.requirePerm(auth.PermAlertPublish, s.handleDrillRun))
	mux.HandleFunc("/api/delivery/stats", s.requirePerm(auth.PermAlertRead, s.handleDeliveryStats))
	mux.HandleFunc("/api/orgs", s.requireRole(auth.RoleUser, s.handleOrgs))
	// Audit trail (RBAC: settings:manage; verifying the global chain is super-only).
	// Read-only view of configured ingress/egress channels (no secrets).
	mux.HandleFunc("/api/sources", s.requirePerm(auth.PermAlertRead, s.handleSources))
	mux.HandleFunc("/api/audit", s.requirePerm(auditPerm, s.handleAudit))
	mux.HandleFunc("/api/audit/verify", s.requirePerm(auditPerm, s.handleAuditVerify))
	mux.HandleFunc("/pubkey", s.handlePubkey)
	// Observability (ARCHITECTURE §6).
	mux.Handle("/metrics", metrics.Handler())
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
	mux.Handle("/admin/", s.adminHandler())
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusMovedPermanently)
	})
	// The lean alert client. Its files are NOT content-hashed, so it is pinned to
	// revalidate-always: a stale life-safety client must never be served from a
	// browser's heuristic cache. See httpcache.go.
	mux.Handle("/", withCacheControl(cacheRevalidate, http.FileServer(http.Dir(s.WebDir))))
	// Compression wraps the whole mux (it no-ops for clients that don't offer gzip,
	// for Range requests, and for already-compressed types like woff2).
	return withGzip(mux)
}

// adminHandler serves the embedded React admin SPA with history-mode fallback.
func (s *Server) adminHandler() http.Handler {
	sub, err := fs.Sub(webadmin.DistFS, "dist")
	if err != nil {
		log.Fatalf("webadmin fs: %v", err)
	}
	fileServer := http.FileServer(http.FS(sub))
	indexHTML, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		log.Fatalf("webadmin index.html: %v", err)
	}
	serveIndex := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(indexHTML)
	}
	return http.StripPrefix("/admin/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p != "" {
			if _, err := fs.Stat(sub, p); err == nil {
				// Vite content-hashes everything under assets/, so those URLs are
				// immutable — a rebuild changes the filename, never the bytes.
				if strings.HasPrefix(p, "assets/") {
					w.Header().Set("Cache-Control", cacheImmutable)
				}
				fileServer.ServeHTTP(w, r) // real file (hashed asset, favicon, …)
				return
			}
			if strings.HasPrefix(p, "assets/") {
				http.NotFound(w, r) // never SPA-fallback a missing hashed asset
				return
			}
		}
		serveIndex(w) // root or client-side route → SPA index (no FileServer redirect)
	}))
}

type publishReq struct {
	Severity string `json:"severity"`
	Category string `json:"category"`
	Title    string `json:"title"`
	Body     string `json:"body"`
	Action   string `json:"action"`
	TTL      int64  `json:"ttl"`
}

func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req publishReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if req.Action == "" {
		req.Action = alert.DefaultAction(req.Category)
	}
	const source = "panel"
	if err := alert.ValidateInput(req.Severity, req.Category, req.Title, req.Body, req.Action, source); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = alert.DefaultTTL(req.Severity)
	}
	a := &alert.Alert{
		SchemaVersion: alert.SchemaVersion,
		ID:            alert.NewID(),
		Type:          "alert",
		Category:      req.Category,
		Severity:      req.Severity,
		Title:         req.Title,
		Body:          req.Body,
		Action:        req.Action,
		Source:        source,
		IssuedAt:      time.Now().Unix(),
		TTL:           ttl,
		Nonce:         alert.NewNonce(),
		Cancels:       "",
	}
	org := s.orgFor(r)
	if err := s.PublishAlert(a, org); err != nil {
		http.Error(w, "publish failed", http.StatusBadGateway)
		return
	}
	s.audit(r, org, AuditAlertPublish, "alert", a.ID, a.Severity+"/"+a.Category+" "+a.Title)
	writeJSON(w, a)
}

// inOrg runs fn against a Store bound to orgID. On Postgres it opens a
// transaction with SET LOCAL app.current_org so RLS applies to the alerts table
// (defense-in-depth) and commits/rolls back around fn; on SQLite it is a direct
// call. Use it for every alerts-table read/write, from HTTP handlers and
// background producers (EEW/CAP) alike — RLS is fail-closed, so a write with no
// org GUC would be rejected under a least-privilege role.
func (s *Server) inOrg(ctx context.Context, orgID int64, fn func(*store.Store) error) error {
	st, tx, err := s.Store.BeginOrg(ctx, orgID)
	if err != nil {
		return err
	}
	if tx == nil {
		return fn(st) // sqlite: no tx, app-level org_id filter is the isolation
	}
	if err := fn(st); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// PublishAlert signs, broadcasts (events + retained active per policy), fans out
// to ntfy + channels, and persists under orgID. Shared by /api/publish, /api/cap, EEW.
func (s *Server) PublishAlert(a *alert.Alert, orgID int64) error {
	alert.Sign(a, s.Priv)
	payload, _ := json.Marshal(a)
	if err := s.Broker.Publish(TopicEvents, payload, false, 1); err != nil {
		return err
	}
	s.maybeSetActive(a, payload)
	if s.Ntfy != nil {
		go s.Ntfy.Publish(a) // independent backup channel, never blocks the hot path
	}
	if err := s.inOrg(context.Background(), orgID, func(st *store.Store) error {
		return st.Save(a, orgID)
	}); err != nil {
		// The alert IS already on the wire at this point — persistence failing
		// degrades history/delivery, it does not lose the broadcast.
		slog.Error("alert persist failed", "alert_id", a.ID, "org_id", orgID, "err", err)
	}
	if s.Delivery.Enabled() {
		s.Delivery.Enqueue(a, orgID, string(payload)) // durable webhook/email outbox
	}
	// Publishing an alert is the single most consequential action in the system;
	// it must always leave a record naming who/what fired it.
	s.TrackForAck(a) // critical/emergency start the §5 ladder; others never escalate
	slog.Info("alert published", "alert_id", a.ID, "severity", a.Severity,
		"category", a.Category, "source", a.Source, "org_id", orgID)
	metrics.AlertsPublished.WithLabelValues(a.Severity, a.Category, a.Source).Inc()
	return nil
}

// RenewAlert re-issues an existing alert under the SAME id with a fresh
// issued_at/ttl/nonce (SPEC §5.2). Clients that already saw the id extend it
// silently; if the severity has risen they present it again as an escalation.
//
// The nonce MUST be fresh — re-using it would make the renewal look like a
// replay to the client's accept gate, which is exactly what the nonce is for.
func (s *Server) RenewAlert(a *alert.Alert, orgID int64) error {
	a.IssuedAt = time.Now().Unix()
	a.Nonce = alert.NewNonce()
	a.Sig = "" // re-signed by PublishAlert over the new canonical bytes
	return s.PublishAlert(a, orgID)
}

// maybeSetActive applies the SPEC §5 replacement policy: overwrite the retained
// active slot only if the new alert is equal-or-higher severity than the current
// one, or the current one has expired.
func (s *Server) maybeSetActive(a *alert.Alert, payload []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	cur := s.active
	curValid := cur != nil && now <= cur.IssuedAt+cur.TTL
	if !curValid || alert.SeverityRank(a.Severity) >= alert.SeverityRank(cur.Severity) {
		s.active = a
		if err := s.Broker.Publish(TopicActive, payload, true, 1); err != nil {
			log.Printf("publish active: %v", err)
		}
	}
}

type cancelReq struct {
	ID string `json:"id"`
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req cancelReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(w, "bad json or missing id", http.StatusBadRequest)
		return
	}
	org := s.orgFor(r)
	c, err := s.CancelByID(req.ID, "panel", org)
	if err != nil {
		http.Error(w, "publish failed", http.StatusBadGateway)
		return
	}
	s.audit(r, org, AuditAlertCancel, "alert", req.ID, "recalled via panel")
	writeJSON(w, c)
}

// CancelByID publishes a signed recall for originalID, clears the retained active
// slot if it held it, and notifies the backup channel (SPEC §5.1). Shared by the
// panel and EEW cancels.
func (s *Server) CancelByID(originalID, source string, orgID int64) (*alert.Alert, error) {
	c := &alert.Alert{
		SchemaVersion: alert.SchemaVersion,
		ID:            alert.NewID(),
		Type:          "cancel",
		Category:      "custom",
		Severity:      "notice",
		Title:         "警报已解除",
		Source:        source,
		IssuedAt:      time.Now().Unix(),
		TTL:           MaxSkew,
		Nonce:         alert.NewNonce(),
		Cancels:       originalID,
	}
	alert.Sign(c, s.Priv)
	payload, _ := json.Marshal(c)
	if err := s.Broker.Publish(TopicEvents, payload, false, 1); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.active != nil && s.active.ID == originalID {
		s.active = nil
		if err := s.Broker.Publish(TopicActive, []byte{}, true, 1); err != nil {
			log.Printf("clear active: %v", err)
		}
	}
	s.mu.Unlock()
	if s.Ntfy != nil {
		go s.Ntfy.Publish(c)
	}
	if err := s.inOrg(context.Background(), orgID, func(st *store.Store) error {
		return st.Save(c, orgID)
	}); err != nil {
		slog.Error("cancel persist failed", "cancel_id", c.ID, "cancels", originalID, "org_id", orgID, "err", err)
	}
	s.StopEscalation(originalID) // a recalled alert must stop nagging
	slog.Info("alert cancelled", "cancels", originalID, "cancel_id", c.ID, "source", source, "org_id", orgID)
	return c, nil
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	org := s.orgFor(r)
	var envs []json.RawMessage
	err := s.inOrg(r.Context(), org, func(st *store.Store) error {
		var e error
		envs, e = st.History(org, 50)
		return e
	})
	if err != nil {
		http.Error(w, "history failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, envs)
}

// handleDeliveryStats surfaces durable-delivery health for the active org: status
// counts (pending/sent/dead) + recent dead-lettered jobs (fail-loud visibility).
func (s *Server) handleDeliveryStats(w http.ResponseWriter, r *http.Request) {
	org := s.orgFor(r)
	counts, err := s.Store.DeliveryStatusCounts(org)
	if err != nil {
		http.Error(w, "delivery stats failed", http.StatusInternalServerError)
		return
	}
	dead, err := s.Store.RecentDeadDeliveries(org, 20)
	if err != nil {
		http.Error(w, "delivery stats failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"counts": counts, "dead": dead})
}

// handlePubkey returns the trust anchor + browser-client bootstrap info (SPEC §7).
// Public on purpose for the local MVP; production embeds the pubkey at build time.
func (s *Server) handlePubkey(w http.ResponseWriter, r *http.Request) {
	// "pubkey" stays for compatibility with anything reading the old shape;
	// "pubkeys" is the ordered accept-list, current key first (SPEC §8).
	writeJSON(w, map[string]any{
		"pubkey":         s.PubB64url,
		"pubkeys":        append([]string{s.PubB64url}, s.PubB64urlExtra...),
		"schema_version": alert.SchemaVersion,
		"max_skew":       MaxSkew,
		"ws_port":        s.WSPort,
		"mqtt_user":      s.ClientUser,
		"mqtt_pw":        s.ClientPass,
	})
}

// RunSweeper clears the retained active slot when its alert expires (SPEC §5.2).
func (s *Server) RunSweeper(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweepExpiredActive()
		}
	}
}

// sweepExpiredActive is one pass of the TTL self-heal (SPEC §5.2): once the
// active alert's TTL has elapsed, clear the retained slot so a client that
// reconnects later does not resurrect a stale emergency. Split out of the ticker
// loop so it can be driven directly by a test instead of waiting for a tick.
func (s *Server) sweepExpiredActive() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil || time.Now().Unix() <= s.active.IssuedAt+s.active.TTL {
		return
	}
	s.active = nil
	if err := s.Broker.Publish(TopicActive, []byte{}, true, 1); err != nil {
		log.Printf("sweeper clear active: %v", err)
	}
}

// selfCheck is the server's verdict on its own health, carried in every signed
// heartbeat (SPEC-SAFETY §3.1). Without it the beat was unconditionally green, so
// a half-broken server kept telling clients everything was fine — the exact
// failure mode fail-loud exists to prevent.
//
// What each dependency means for alert flow:
//   - store unreachable: alerts still sign and publish (PublishAlert only LOGS a
//     save failure), but history, delivery and auth are broken -> DEGRADED, not dead.
//   - broker unreachable: the beat itself cannot be published, so the client
//     watchdog fires on its own. We still report it on the next beat, in case the
//     failure was transient and only some publishes were lost.
//
// It deliberately never stops the beat: reporting "I am degraded" is strictly more
// informative than going silent, and silence is already covered by the watchdog.
func (s *Server) selfCheck() (health string, reason string) {
	if err := s.Store.Ping(); err != nil {
		return alert.HealthDegraded, "store unreachable: " + err.Error()
	}
	s.mu.Lock()
	lastErr := s.lastPublishErr
	s.mu.Unlock()
	if lastErr != "" {
		return alert.HealthDegraded, "last broker publish failed: " + lastErr
	}
	return alert.HealthOK, ""
}

// SelfCheckHealthy is the watchdog's view of selfCheck: the same verdict that
// feeds the signed heartbeat, so the A and B layers can never disagree about
// whether this server considers itself healthy.
func (s *Server) SelfCheckHealthy() (bool, string) {
	health, reason := s.selfCheck()
	return health == alert.HealthOK, reason
}

// notePublishResult records whether the most recent broker publish worked, so the
// next heartbeat can report a broker that is failing under us.
func (s *Server) notePublishResult(err error) {
	s.mu.Lock()
	if err != nil {
		s.lastPublishErr = err.Error()
	} else {
		s.lastPublishErr = ""
	}
	s.mu.Unlock()
}

// RunHeartbeat publishes the signed FAIL-LOUD liveness beacon every
// HeartbeatInterval seconds (SPEC-SAFETY §3.1). Clients run a local watchdog and
// alarm if it stops — silence must never be mistaken for "no alerts".
func (s *Server) RunHeartbeat(ctx context.Context) {
	var seq int64
	var lastReason string
	beat := func() {
		seq++
		s.mu.Lock()
		active := 0
		if s.active != nil && time.Now().Unix() <= s.active.IssuedAt+s.active.TTL {
			active = 1
		}
		s.mu.Unlock()
		health, reason := s.selfCheck()
		if reason != lastReason {
			if reason != "" {
				slog.Error("heartbeat reporting DEGRADED", "reason", reason)
			} else {
				slog.Info("heartbeat recovered", "health", alert.HealthOK)
			}
			lastReason = reason
		}
		hb := &alert.Heartbeat{
			SchemaVersion: alert.SchemaVersion,
			Type:          "heartbeat",
			Seq:           seq,
			IssuedAt:      time.Now().Unix(),
			Interval:      HeartbeatInterval,
			ActiveCount:   active,
			Health:        health,
		}
		alert.SignHeartbeat(hb, s.Priv)
		payload, _ := json.Marshal(hb)
		err := s.Broker.Publish(TopicHeartbeat, payload, true, 1)
		if err != nil {
			log.Printf("heartbeat publish: %v", err)
		}
		s.notePublishResult(err)
		metrics.Heartbeats.WithLabelValues(health).Inc()
	}
	beat() // emit one immediately so a just-connected client gets a retained beat
	t := time.NewTicker(time.Duration(HeartbeatInterval) * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			beat()
		}
	}
}

// handleHealthz is liveness: the process is up.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// handleReadyz is readiness: dependencies (DB) reachable.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if err := s.Store.Ping(); err != nil {
		http.Error(w, "db unreachable", http.StatusServiceUnavailable)
		return
	}
	// Carry build identity: a self-hoster filing a bug, and any fleet-wide check,
	// needs to know which build answered.
	writeJSON(w, map[string]any{
		"ready": true, "version": obs.Version(), "commit": obs.Commit(),
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// Every JSON response here is either per-request state, authenticated data, or
	// the /pubkey bootstrap (trust anchor + broker password) — none of it may be
	// written to a browser or proxy cache.
	w.Header().Set("Cache-Control", cacheNoStore)
	_ = json.NewEncoder(w).Encode(v)
}
