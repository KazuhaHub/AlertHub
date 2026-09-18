// Command alerthub is the single-binary AlertHub server: it embeds the MQTT
// broker (TCP + WebSocket), signs alerts with Ed25519, serves the web UI, and
// exposes the publish/cancel HTTP API. One command, zero external deps.
//
// Run from the repo root:  go run ./server   (or `make run`)
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/KazuhaHub/AlertHub/server/internal/alert"
	"github.com/KazuhaHub/AlertHub/server/internal/api"
	"github.com/KazuhaHub/AlertHub/server/internal/auth"
	"github.com/KazuhaHub/AlertHub/server/internal/broker"
	"github.com/KazuhaHub/AlertHub/server/internal/delivery"
	"github.com/KazuhaHub/AlertHub/server/internal/eew"
	"github.com/KazuhaHub/AlertHub/server/internal/ntfy"
	"github.com/KazuhaHub/AlertHub/server/internal/obs"
	"github.com/KazuhaHub/AlertHub/server/internal/passkey"
	"github.com/KazuhaHub/AlertHub/server/internal/siem"
	"github.com/KazuhaHub/AlertHub/server/internal/sso"
	"github.com/KazuhaHub/AlertHub/server/internal/store"
	"github.com/KazuhaHub/AlertHub/server/internal/twofa"
	"github.com/KazuhaHub/AlertHub/server/internal/watchdog"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// parseDuration is a forgiving env parser: a typo must not silently disable a
// safety mechanism, so it falls back to the default and says so.
func parseDuration(v string, def time.Duration) time.Duration {
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		if v != "" {
			log.Printf("invalid duration %q, using %s", v, def)
		}
		return def
	}
	return d
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func main() {
	var (
		httpAddr   = env("ALERTHUB_HTTP_ADDR", ":8080")
		tcpAddr    = env("ALERTHUB_MQTT_TCP", ":1883")
		wsAddr     = env("ALERTHUB_MQTT_WS", ":1884")
		webDir     = env("ALERTHUB_WEB_DIR", "web")
		keyDir     = env("ALERTHUB_KEY_DIR", "keys")
		dbPath     = env("ALERTHUB_DB_PATH", "alerthub.db")
		dbDriver   = env("ALERTHUB_DB_DRIVER", "sqlite") // "sqlite" | "postgres"
		dbDSN      = env("ALERTHUB_DB_DSN", "")          // postgres connection string
		adminToken = env("ALERTHUB_ADMIN_TOKEN", "dev-admin-token")
		pubUser    = env("ALERTHUB_MQTT_USER", "publisher")
		pubPass    = env("ALERTHUB_MQTT_PW", "dev-publisher-pw")
		cliUser    = env("ALERTHUB_CLIENT_USER", "client")
		cliPass    = env("ALERTHUB_CLIENT_PW", "dev-client-pw")
		// ntfy independent backup channel (SPEC-SAFETY §4); empty = disabled.
		ntfyURL    = env("ALERTHUB_NTFY_URL", "")
		ntfyToken  = env("ALERTHUB_NTFY_TOKEN", "")
		ntfyPrefix = env("ALERTHUB_NTFY_TOPIC_PREFIX", "alerthub-")
		ntfyPublic = env("ALERTHUB_NTFY_SH_TOPIC", "")
		// First-run admin seed (Passwall-style admin login).
		adminUser = env("ALERTHUB_ADMIN_USER", "admin")
		adminPass = env("ALERTHUB_ADMIN_PASS", "")
		// Passkey/WebAuthn Relying Party (RP-ID from config, never Host header).
		rpID     = env("ALERTHUB_RP_ID", "localhost")
		rpOrigin = env("ALERTHUB_RP_ORIGIN", "http://localhost:8080")
	)
	// Structured logging first: everything below (including the standard log
	// package, which slog.SetDefault re-routes) then emits parseable records.
	obs.Setup(env("ALERTHUB_LOG_FORMAT", "json"), env("ALERTHUB_LOG_LEVEL", "info"))
	// NB: no "version" attr here — obs.Setup already binds it to every record, and
	// repeating it emits a duplicate JSON key that some log pipelines reject.
	slog.Info("starting", "commit", obs.Commit(),
		"http_addr", httpAddr, "db_driver", dbDriver)
	if adminToken == "dev-admin-token" {
		slog.Warn("using the default admin token — set ALERTHUB_ADMIN_TOKEN for anything but local dev")
	}

	priv, pubB64, err := loadOrGenKeys(keyDir)
	if err != nil {
		log.Fatalf("keys: %v", err)
	}

	// mochi is chatty at info; keep it at warn but on the same structured handler.
	logger := slog.Default().With("component", "broker")
	b, err := broker.New(tcpAddr, wsAddr, broker.Creds{
		PublisherUser: pubUser, PublisherPass: pubPass,
		ClientUser: cliUser, ClientPass: cliPass,
	}, logger)
	if err != nil {
		log.Fatalf("broker: %v", err)
	}
	if err := b.Start(); err != nil {
		log.Fatalf("broker serve: %v", err)
	}

	var st *store.Store
	if dbDriver == "postgres" {
		if dbDSN == "" {
			log.Fatal("store: ALERTHUB_DB_DRIVER=postgres requires ALERTHUB_DB_DSN")
		}
		st, err = store.OpenPostgres(dbDSN)
		log.Printf("store: postgres (enterprise tier)")
	} else {
		st, err = store.Open(dbPath)
	}
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	jwtSecret, err := loadOrGenJWTSecret(keyDir)
	if err != nil {
		log.Fatalf("jwt secret: %v", err)
	}
	authSvc := auth.New(jwtSecret)
	if err := seedAdmin(st, adminUser, adminPass); err != nil {
		log.Fatalf("seed admin: %v", err)
	}
	// Multi-tenancy (M1): ensure the default org + migrate pre-tenancy data/users.
	defaultOrg, err := st.EnsureDefaultOrg()
	if err != nil {
		log.Fatalf("default org: %v", err)
	}
	if err := st.BackfillMemberships(defaultOrg); err != nil {
		log.Printf("backfill memberships: %v", err)
	}
	if err := st.BackfillOrgID(defaultOrg); err != nil {
		log.Printf("backfill org_id: %v", err)
	}
	passkeySvc, err := passkey.New(st, rpID, rpOrigin, "AlertHub")
	if err != nil {
		log.Fatalf("passkey: %v", err)
	}
	kek, err := loadOrGenKEK(keyDir)
	if err != nil {
		log.Fatalf("kek: %v", err)
	}
	twofaSvc := twofa.New(st, kek, "AlertHub")

	oidcSvc, err := sso.NewOIDC(context.Background(), sso.OIDCConfig{
		Enabled:      env("ALERTHUB_OIDC_ENABLED", "") == "true",
		IssuerURL:    env("ALERTHUB_OIDC_ISSUER", ""),
		ClientID:     env("ALERTHUB_OIDC_CLIENT_ID", ""),
		ClientSecret: env("ALERTHUB_OIDC_CLIENT_SECRET", ""),
		RedirectURL:  env("ALERTHUB_OIDC_REDIRECT", "http://localhost:8080/api/auth/oidc/callback"),
	})
	if err != nil {
		log.Printf("OIDC disabled (discovery failed): %v", err)
		oidcSvc = sso.Disabled()
	} else if oidcSvc.Enabled() {
		log.Printf("OIDC SSO enabled")
	}

	samlEntity := env("ALERTHUB_SAML_ENTITY_ID", "http://localhost:8080/api/auth/saml/metadata")
	samlSvc, err := sso.NewSAML(sso.SAMLConfig{
		Enabled:        env("ALERTHUB_SAML_ENABLED", "") == "true",
		EntityID:       samlEntity,
		ACSURL:         env("ALERTHUB_SAML_ACS", "http://localhost:8080/api/auth/saml/acs"),
		MetadataURL:    env("ALERTHUB_SAML_METADATA_URL", samlEntity),
		IDPMetadataXML: env("ALERTHUB_SAML_IDP_METADATA", ""),
		IDPMetadataURL: env("ALERTHUB_SAML_IDP_METADATA_URL", ""),
		AttrUsername:   env("ALERTHUB_SAML_ATTR_USERNAME", "nameid"),
		AttrEmail:      env("ALERTHUB_SAML_ATTR_EMAIL", "email"),
		AttrName:       env("ALERTHUB_SAML_ATTR_NAME", "displayName"),
		AttrGroups:     env("ALERTHUB_SAML_ATTR_GROUPS", "groups"),
		// Secure-by-default: IdP-initiated SSO is opt-in (CSRF/replay surface).
		AllowIDPInitiated: env("ALERTHUB_SAML_ALLOW_IDP_INITIATED", "") == "true",
	})
	if err != nil {
		log.Printf("SAML disabled (%v)", err)
		samlSvc = &sso.SAML{}
	} else if samlSvc.Enabled() {
		log.Printf("SAML SSO enabled")
	}

	wsPort := wsAddr
	if _, p, err := net.SplitHostPort(wsAddr); err == nil {
		wsPort = p
	}
	ntfyPub := ntfy.New(ntfy.Config{
		BaseURL: ntfyURL, Token: ntfyToken, TopicPrefix: ntfyPrefix, PublicTopic: ntfyPublic,
	})
	// Durable delivery pipeline (transactional outbox): webhook (all severities) +
	// email (critical/emergency). Supersedes the in-proc fire-and-forget dispatcher.
	var senders []delivery.Sender
	if urls := splitCSV(env("ALERTHUB_WEBHOOK_URLS", "")); len(urls) > 0 {
		senders = append(senders, delivery.NewWebhookSender(urls))
	}
	if smtpHost := env("ALERTHUB_SMTP_HOST", ""); smtpHost != "" {
		if to := splitCSV(env("ALERTHUB_ALERT_EMAILS", "")); len(to) > 0 {
			senders = append(senders, &delivery.EmailSender{
				Host: smtpHost, Port: env("ALERTHUB_SMTP_PORT", "587"),
				User: env("ALERTHUB_SMTP_USER", ""), Pass: env("ALERTHUB_SMTP_PASS", ""),
				From: env("ALERTHUB_SMTP_FROM", ""), To: to,
			})
		}
	}
	deliveryMgr := delivery.New(st, delivery.Config{}, senders...)
	// The rate limiter and the audit trail both key on the client address, so a
	// deployment that terminates TLS at a reverse proxy (as SECURITY.md
	// recommends) has to say which peers may speak for a client. Left unset, the
	// TCP peer is used and X-Forwarded-For is ignored -- the behaviour of every
	// release before this setting existed.
	// Default: a proxy on the same host. That is the deployment SECURITY.md
	// describes, and spoofing X-Forwarded-For past it requires already being on
	// the machine. Set "none" to key on the TCP peer unconditionally.
	trustedProxies, err := api.ParseTrustedProxies(env("ALERTHUB_TRUSTED_PROXIES", "loopback"))
	if err != nil {
		// Falling back means the limiter keys on the proxy again, so say exactly
		// what that costs instead of letting a typo quietly undo the setting.
		slog.Error("ALERTHUB_TRUSTED_PROXIES is invalid; ignoring X-Forwarded-For. "+
			"Behind a reverse proxy every client now shares one rate-limit bucket "+
			"and the audit trail records the proxy address",
			"err", err)
		trustedProxies = api.TrustedProxies{}
	}
	switch {
	case trustedProxies.Configured():
		log.Printf("trusted proxies: %s (X-Forwarded-For honoured from these peers)", env("ALERTHUB_TRUSTED_PROXIES", "loopback"))
	default:
		log.Printf("trusted proxies: none (X-Forwarded-For ignored; every client behind a reverse proxy shares one rate-limit bucket)")
	}

	srv := &api.Server{
		Broker: b, Store: st, Priv: priv, PubB64url: pubB64,
		AdminToken: adminToken, WebDir: webDir,
		TrustedProxies: trustedProxies,
		// Rotation overlap: keys listed here are accepted but never used to sign.
		PubB64urlExtra: splitCSV(env("ALERTHUB_PUBKEYS_EXTRA", "")),
		WSPort:         wsPort, ClientUser: cliUser, ClientPass: cliPass,
		Ntfy: ntfyPub, Delivery: deliveryMgr, Auth: authSvc, Passkey: passkeySvc, TwoFA: twofaSvc,
		OIDC: oidcSvc, SAML: samlSvc, OIDCDefaultRole: env("ALERTHUB_OIDC_DEFAULT_ROLE", "admin"),
		EEWEnabled:         env("ALERTHUB_EEW", "") == "wolfx",
		WatchdogConfigured: env("ALERTHUB_WATCHDOG_URL", "") != "",
		SIEMConfigured:     env("ALERTHUB_SIEM_URL", "") != "",
		DefaultOrgID:       defaultOrg,
	}
	if ntfyPub.Enabled() {
		log.Printf("ntfy backup channel: self=%q public=%q", ntfyURL, ntfyPublic)
	} else {
		log.Printf("ntfy backup channel: disabled (set ALERTHUB_NTFY_URL / ALERTHUB_NTFY_SH_TOPIC)")
	}

	if err := b.Subscribe("status/#", srv.OnPresence); err != nil {
		slog.Error("presence subscribe failed", "err", err)
	}
	// SPEC §5.3: collect the acks clients have always been publishing. Without
	// this subscription the "who has confirmed" roster does not exist.
	if err := b.Subscribe(api.TopicAckFilter, srv.OnAck); err != nil {
		slog.Error("ack subscribe failed", "err", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.RunSweeper(ctx)
	go srv.RunHeartbeat(ctx)
	go srv.RunEscalator(ctx) // SPEC-SAFETY §5 ladder
	// SPEC-SAFETY §3.4: prove the chain works before it is needed. Off by default
	// — a drill publishes a REAL alert, so switching it on is a deliberate act.
	drillCfg := api.DefaultDrillConfig()
	drillCfg.Enabled = env("ALERTHUB_DRILL", "") == "true"
	if v := env("ALERTHUB_DRILL_WINDOW", ""); v != "" {
		drillCfg.Window = parseDuration(v, drillCfg.Window)
	}
	srv.DrillCfg = drillCfg
	go srv.RunDrills(ctx, drillCfg)
	if deliveryMgr.Enabled() {
		log.Printf("delivery pipeline: %d channel(s), durable outbox", len(senders))
		go deliveryMgr.RunWorker(ctx)
	}

	// B-layer fail-loud: a dead-man switch held by a third party, so that "the
	// whole house went dark" is noticed by someone other than the dead host.
	wd := watchdog.New(watchdog.Config{
		URL:      env("ALERTHUB_WATCHDOG_URL", ""),
		Interval: parseDuration(env("ALERTHUB_WATCHDOG_INTERVAL", "60s"), time.Minute),
	}, srv.SelfCheckHealthy)
	go wd.Run(ctx)

	// Audit retention. An append-only log grows without bound, which on a
	// self-hosted box eventually fills the disk — so retention is a safety
	// feature, not housekeeping. Pruning records itself and anchors the chain so
	// a shortened log still verifies (see store.PruneAudit).
	if days := parseDuration(env("ALERTHUB_AUDIT_RETENTION", ""), 0); days > 0 {
		go func() {
			t := time.NewTicker(6 * time.Hour)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					cutoff := time.Now().Add(-days).Unix()
					n, err := st.PruneAudit(cutoff, "retention")
					if err != nil {
						slog.Error("audit prune failed", "err", err)
					} else if n > 0 {
						slog.Info("audit pruned", "entries", n, "older_than", days.String())
					}
				}
			}
		}()
		slog.Info("audit retention enabled", "keep", days.String())
	}

	// SIEM export: ship the audit trail off-host so it survives a compromise of
	// this one (ARCHITECTURE §8). Disabled unless a collector URL is configured.
	siemExp := siem.New(st, siem.Config{
		URL:   env("ALERTHUB_SIEM_URL", ""),
		Token: env("ALERTHUB_SIEM_TOKEN", ""),
	})
	if siemExp.Enabled() {
		go siemExp.Run(ctx)
	}

	// ALERTHUB_EEW is a CSV of relays, e.g. "wolfx,p2pquake". Two independent
	// sources is what SPEC-SAFETY §6.1 asks for; they share one deduper so a
	// quake both report still fires a single alert.
	if eewSources := splitCSV(env("ALERTHUB_EEW", "")); len(eewSources) > 0 {
		slog.Info("EEW sources enabled (complements official cell broadcast)", "sources", eewSources)
		eew.Run(ctx, eewSources, func(ev eew.Event) {
			// One alert id per earthquake, shared by both relays and by every
			// revision of it — that is what lets §5.2 treat a revision as an
			// update to the SAME warning instead of a competing second one.
			id := "eew-" + ev.EventID
			if ev.IsCancel {
				_, _ = srv.CancelByID(id, "eew", srv.DefaultOrgID)
				return
			}
			a := &alert.Alert{
				SchemaVersion: alert.SchemaVersion,
				ID:            id,
				Type:          "alert",
				Category:      "earthquake",
				Severity:      ev.Severity,
				Title:         ev.Title,
				Body:          ev.Body,
				Action:        ev.Action,
				Source:        "eew",
				IssuedAt:      time.Now().Unix(),
				TTL:           120,
				Nonce:         alert.NewNonce(),
			}
			if ev.IsUpgrade {
				// The intensity was revised upward. Re-issue under the same id:
				// clients that already saw it will re-present rather than extend,
				// because the instruction to the person reading it has changed.
				slog.Warn("EEW intensity revised UPWARD — re-alarming",
					"event_id", ev.EventID, "severity", ev.Severity, "serial", ev.Serial)
				if err := srv.RenewAlert(a, srv.DefaultOrgID); err != nil {
					slog.Error("eew upgrade publish failed", "event_id", ev.EventID, "err", err)
				}
				return
			}
			if err := srv.PublishAlert(a, srv.DefaultOrgID); err != nil {
				slog.Error("eew publish failed", "event_id", ev.EventID, "err", err)
			}
		})
	}

	httpSrv := &http.Server{Addr: httpAddr, Handler: srv.Handler()}
	go func() {
		log.Printf("AlertHub up — client (browser will Arm + verify):")
		log.Printf("  panel:  http://localhost%s/publish.html", httpAddr)
		log.Printf("  client: http://localhost%s/", httpAddr)
		log.Printf("  mqtt/tcp %s   mqtt/ws %s (browser connects ws://localhost%s)", tcpAddr, wsAddr, wsAddr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("http: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down…")
	cancel()
	shutCtx, sc := context.WithTimeout(context.Background(), 3*time.Second)
	defer sc()
	_ = httpSrv.Shutdown(shutCtx)
	_ = b.Stop()
}

// loadOrGenKeys loads the Ed25519 keypair from dir, generating it on first run
// (SPEC §8). Private key: base64-std of the 64-byte key, 0600. Public key:
// base64url raw 32 bytes, 0644 (also what /pubkey serves).
func loadOrGenKeys(dir string) (ed25519.PrivateKey, string, error) {
	privPath := filepath.Join(dir, "alerthub_ed25519.key")
	pubPath := filepath.Join(dir, "alerthub_ed25519.pub")

	if data, err := os.ReadFile(privPath); err == nil {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil || len(raw) != ed25519.PrivateKeySize {
			return nil, "", errors.New("invalid private key file (expected base64 of 64 bytes)")
		}
		priv := ed25519.PrivateKey(raw)
		pub := priv.Public().(ed25519.PublicKey)
		return priv, base64.RawURLEncoding.EncodeToString(pub), nil
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(privPath, []byte(base64.StdEncoding.EncodeToString(priv)), 0o600); err != nil {
		return nil, "", err
	}
	pubB64 := base64.RawURLEncoding.EncodeToString(pub)
	if err := os.WriteFile(pubPath, []byte(pubB64), 0o644); err != nil {
		return nil, "", err
	}
	log.Printf("generated new Ed25519 keypair in %s/", dir)
	return priv, pubB64, nil
}

// loadOrGenJWTSecret loads (or generates + persists) the HS256 signing secret.
func loadOrGenJWTSecret(dir string) ([]byte, error) {
	p := filepath.Join(dir, "jwt_secret")
	if data, err := os.ReadFile(p); err == nil {
		if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data))); err == nil && len(raw) >= 32 {
			return raw, nil
		}
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, []byte(base64.StdEncoding.EncodeToString(secret)), 0o600); err != nil {
		return nil, err
	}
	log.Printf("generated new JWT secret in %s/", dir)
	return secret, nil
}

// loadOrGenKEK loads (or generates + persists) the 32-byte AES-256 key-encryption
// key used by secretbox to encrypt TOTP secrets (and later IdP secrets) at rest.
func loadOrGenKEK(dir string) ([]byte, error) {
	p := filepath.Join(dir, "kek")
	if data, err := os.ReadFile(p); err == nil {
		if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data))); err == nil && len(raw) == 32 {
			return raw, nil
		}
	}
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, []byte(base64.StdEncoding.EncodeToString(kek)), 0o600); err != nil {
		return nil, err
	}
	log.Printf("generated new KEK (secrets-at-rest) in %s/", dir)
	return kek, nil
}

// seedAdmin creates the first admin on a fresh DB. With no ALERTHUB_ADMIN_PASS,
// a random password is generated and printed once.
func seedAdmin(st *store.Store, user, pass string) error {
	n, err := st.CountUsers()
	if err != nil || n > 0 {
		return err
	}
	if pass == "" {
		b := make([]byte, 9)
		_, _ = rand.Read(b)
		pass = base64.RawURLEncoding.EncodeToString(b)
		log.Printf("┌─ AlertHub first-run admin ────────────────────")
		log.Printf("│  user: %s", user)
		log.Printf("│  pass: %s", pass)
		log.Printf("│  (set ALERTHUB_ADMIN_PASS to choose your own)")
		log.Printf("└───────────────────────────────────────────────")
	} else {
		log.Printf("seeded admin %q from ALERTHUB_ADMIN_PASS", user)
	}
	hash, err := auth.HashPassword(pass)
	if err != nil {
		return err
	}
	id, err := st.CreateUser(&store.User{UPN: user, PasswordHash: hash, Role: auth.RoleAdmin, Enabled: true})
	if err != nil {
		return err
	}
	return st.MakeSuperadmin(id) // bootstrap admin is the platform super-admin
}
