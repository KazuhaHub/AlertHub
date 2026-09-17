package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/AlertHub/server/internal/alert"
	"github.com/KazuhaHub/AlertHub/server/internal/auth"
	"github.com/KazuhaHub/AlertHub/server/internal/broker"
	"github.com/KazuhaHub/AlertHub/server/internal/delivery"
	"github.com/KazuhaHub/AlertHub/server/internal/passkey"
	"github.com/KazuhaHub/AlertHub/server/internal/store"
	"github.com/KazuhaHub/AlertHub/server/internal/twofa"
)

const testAdminToken = "test-admin-token"

// testServer builds a full, wired Server against an in-process broker (random
// ports) and a temp-file SQLite store, plus its HTTP handler. It exercises the
// real routing + auth middleware, not handlers in isolation.
type testServer struct {
	srv     *Server
	handler http.Handler
	pub     ed25519.PublicKey
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return newTestServerWithStore(t, st)
}

// newTestServerWithStore wires a full Server (in-process broker on random ports)
// around a caller-provided store, so the same tests can run on SQLite or Postgres.
func newTestServerWithStore(t *testing.T, st *store.Store) *testServer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	b, err := broker.New(":0", ":0", broker.Creds{
		PublisherUser: "p", PublisherPass: "pp", ClientUser: "c", ClientPass: "cp",
	}, logger)
	if err != nil {
		t.Fatalf("broker: %v", err)
	}
	if err := b.Start(); err != nil {
		t.Fatalf("broker start: %v", err)
	}
	t.Cleanup(func() { _ = b.Stop() })

	orgID, err := st.EnsureDefaultOrg()
	if err != nil {
		t.Fatalf("default org: %v", err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("secret: %v", err)
	}
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatalf("kek: %v", err)
	}
	pk, err := passkey.New(st, "localhost", "http://localhost:8080", "AlertHub")
	if err != nil {
		t.Fatalf("passkey: %v", err)
	}
	srv := &Server{
		Broker:       b,
		Store:        st,
		TwoFA:        twofa.New(st, kek, "AlertHub"),
		Passkey:      pk,
		Priv:         priv,
		PubB64url:    base64.RawURLEncoding.EncodeToString(pub),
		AdminToken:   testAdminToken,
		Auth:         auth.New(secret),
		Delivery:     delivery.New(st, delivery.Config{}), // no senders => disabled, hot path skips it
		DefaultOrgID: orgID,
	}
	return &testServer{srv: srv, handler: srv.Handler(), pub: pub}
}

// TestPostgres_PublishHistoryE2E drives the real HTTP handlers against Postgres,
// so the publish→inOrg→BeginOrg(SET LOCAL)→commit and history→inOrg→read paths run
// as actual transactions (not the SQLite no-op). Uses two freshly-created orgs so it
// is hermetic regardless of rows left by earlier runs. Gated on ALERTHUB_TEST_PG_DSN.
func TestPostgres_PublishHistoryE2E(t *testing.T) {
	dsn := os.Getenv("ALERTHUB_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("set ALERTHUB_TEST_PG_DSN to run the Postgres HTTP E2E test")
	}
	st, err := store.OpenPostgres(dsn)
	if err != nil {
		t.Fatalf("OpenPostgres: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ts := newTestServerWithStore(t, st)

	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	orgA, err := st.CreateOrg("e2e-a-"+suffix, "A")
	if err != nil {
		t.Fatalf("create org A: %v", err)
	}
	orgB, err := st.CreateOrg("e2e-b-"+suffix, "B")
	if err != nil {
		t.Fatalf("create org B: %v", err)
	}

	pub := func(org int64, title string) {
		body := validPublish()
		body.Title = title
		h := adminHdr()
		h["X-Org-Id"] = itoa(org)
		if w := ts.req(t, http.MethodPost, "/api/publish", body, h); w.Code != http.StatusOK {
			t.Fatalf("publish to org %d = %d; body=%s", org, w.Code, w.Body.String())
		}
	}
	pub(orgA, "e2e-A")
	pub(orgB, "e2e-B")

	histOf := func(org int64) []alert.Alert {
		h := adminHdr()
		h["X-Org-Id"] = itoa(org)
		w := ts.req(t, http.MethodGet, "/api/history", nil, h)
		if w.Code != http.StatusOK {
			t.Fatalf("history org %d = %d", org, w.Code)
		}
		var out []alert.Alert
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode history: %v", err)
		}
		return out
	}
	if h := histOf(orgA); len(h) != 1 || h[0].Title != "e2e-A" {
		t.Fatalf("org A history = %+v, want only e2e-A", h)
	}
	if h := histOf(orgB); len(h) != 1 || h[0].Title != "e2e-B" {
		t.Fatalf("org B history = %+v, want only e2e-B", h)
	}
}

// req sends a request through the full mux and returns the recorder.
func (ts *testServer) req(t *testing.T, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		r = bytes.NewReader(buf)
	}
	rr := httptest.NewRequest(method, path, r)
	for k, v := range headers {
		rr.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	ts.handler.ServeHTTP(w, rr)
	return w
}

func adminHdr() map[string]string {
	return map[string]string{"Authorization": "Bearer " + testAdminToken}
}

// seedUser creates an enabled user with a membership role in the default org and
// returns a valid access token for it.
func (ts *testServer) seedUser(t *testing.T, upn, membershipRole string) string {
	t.Helper()
	hash, err := auth.HashPassword("pw")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	uid, err := ts.srv.Store.CreateUser(&store.User{UPN: upn, PasswordHash: hash, Role: auth.RoleUser, Enabled: true})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := ts.srv.Store.AddMembership(ts.srv.DefaultOrgID, uid, membershipRole); err != nil {
		t.Fatalf("add membership: %v", err)
	}
	access, _, err := ts.srv.Auth.IssueTokens(uid, upn, auth.RoleUser, 0)
	if err != nil {
		t.Fatalf("issue tokens: %v", err)
	}
	return access
}

func userHdr(access string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + access}
}

func validPublish() publishReq {
	return publishReq{Severity: "emergency", Category: "earthquake", Title: "地震", Body: "test", Action: "趴下"}
}

func TestPubkey_PublicAndCorrect(t *testing.T) {
	ts := newTestServer(t)
	w := ts.req(t, http.MethodGet, "/pubkey", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("pubkey status = %d, want 200", w.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["pubkey"] != ts.srv.PubB64url {
		t.Errorf("pubkey = %v, want %v", got["pubkey"], ts.srv.PubB64url)
	}
	if got["max_skew"].(float64) != float64(MaxSkew) {
		t.Errorf("max_skew = %v, want %d", got["max_skew"], MaxSkew)
	}
}

func TestHealthz(t *testing.T) {
	ts := newTestServer(t)
	w := ts.req(t, http.MethodGet, "/healthz", nil, nil)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "ok" {
		t.Fatalf("healthz = %d %q, want 200 ok", w.Code, w.Body.String())
	}
}

func TestReadyz(t *testing.T) {
	ts := newTestServer(t)
	w := ts.req(t, http.MethodGet, "/readyz", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("readyz = %d, want 200 (store reachable)", w.Code)
	}
}

func TestPublish_RequiresAuth(t *testing.T) {
	ts := newTestServer(t)
	w := ts.req(t, http.MethodPost, "/api/publish", validPublish(), nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauth publish = %d, want 401", w.Code)
	}
}

func TestPublish_AdminTokenSignsValidAlert(t *testing.T) {
	ts := newTestServer(t)
	w := ts.req(t, http.MethodPost, "/api/publish", validPublish(), adminHdr())
	if w.Code != http.StatusOK {
		t.Fatalf("publish = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var a alert.Alert
	if err := json.Unmarshal(w.Body.Bytes(), &a); err != nil {
		t.Fatalf("decode alert: %v", err)
	}
	if a.ID == "" || a.Nonce == "" || a.Sig == "" {
		t.Fatalf("server must fill id/nonce/sig, got %+v", a)
	}
	if a.Type != "alert" || a.Severity != "emergency" || a.Category != "earthquake" {
		t.Errorf("unexpected envelope fields: %+v", a)
	}
	if !alert.Verify(&a, ts.pub) {
		t.Fatal("published alert does not verify against the server public key")
	}
}

func TestPublish_ValidatesInput(t *testing.T) {
	ts := newTestServer(t)
	cases := map[string]publishReq{
		"bad severity":     {Severity: "boom", Category: "earthquake", Title: "t"},
		"bad category":     {Severity: "warning", Category: "meteor", Title: "t"},
		"newline in title": {Severity: "warning", Category: "fire", Title: "a\nb"},
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			w := ts.req(t, http.MethodPost, "/api/publish", body, adminHdr())
			if w.Code != http.StatusBadRequest {
				t.Fatalf("%s: status = %d, want 400", name, w.Code)
			}
		})
	}
}

func TestPublish_RBAC(t *testing.T) {
	ts := newTestServer(t)
	// viewer lacks alert:publish
	viewer := ts.seedUser(t, "viewer@x", "viewer")
	if w := ts.req(t, http.MethodPost, "/api/publish", validPublish(), userHdr(viewer)); w.Code != http.StatusForbidden {
		t.Fatalf("viewer publish = %d, want 403", w.Code)
	}
	// dispatcher has alert:publish
	dispatcher := ts.seedUser(t, "dispatcher@x", "dispatcher")
	if w := ts.req(t, http.MethodPost, "/api/publish", validPublish(), userHdr(dispatcher)); w.Code != http.StatusOK {
		t.Fatalf("dispatcher publish = %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

func TestPublish_RejectsRevokedToken(t *testing.T) {
	ts := newTestServer(t)
	access := ts.seedUser(t, "revoke@x", "dispatcher")
	// works before revocation
	if w := ts.req(t, http.MethodPost, "/api/publish", validPublish(), userHdr(access)); w.Code != http.StatusOK {
		t.Fatalf("pre-revoke publish = %d, want 200", w.Code)
	}
	// bump token version => all existing JWTs are invalid
	u, _ := ts.srv.Store.GetUserByUPN("revoke@x")
	if err := ts.srv.Store.BumpTokenVersion(u.ID); err != nil {
		t.Fatalf("bump: %v", err)
	}
	if w := ts.req(t, http.MethodPost, "/api/publish", validPublish(), userHdr(access)); w.Code != http.StatusUnauthorized {
		t.Fatalf("post-revoke publish = %d, want 401", w.Code)
	}
}

func TestHistory_AuthAndReadback(t *testing.T) {
	ts := newTestServer(t)
	if w := ts.req(t, http.MethodGet, "/api/history", nil, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauth history = %d, want 401", w.Code)
	}
	// publish one, then read it back
	pw := ts.req(t, http.MethodPost, "/api/publish", validPublish(), adminHdr())
	if pw.Code != http.StatusOK {
		t.Fatalf("publish = %d", pw.Code)
	}
	hw := ts.req(t, http.MethodGet, "/api/history", nil, adminHdr())
	if hw.Code != http.StatusOK {
		t.Fatalf("history = %d, want 200", hw.Code)
	}
	var hist []alert.Alert
	if err := json.Unmarshal(hw.Body.Bytes(), &hist); err != nil {
		t.Fatalf("decode history: %v", err)
	}
	if len(hist) != 1 || hist[0].Title != "地震" {
		t.Fatalf("history = %+v, want 1 entry titled 地震", hist)
	}
}

func TestCancel(t *testing.T) {
	ts := newTestServer(t)
	if w := ts.req(t, http.MethodPost, "/api/cancel", cancelReq{ID: "x"}, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauth cancel = %d, want 401", w.Code)
	}
	// publish then cancel by id
	pw := ts.req(t, http.MethodPost, "/api/publish", validPublish(), adminHdr())
	var a alert.Alert
	_ = json.Unmarshal(pw.Body.Bytes(), &a)

	cw := ts.req(t, http.MethodPost, "/api/cancel", cancelReq{ID: a.ID}, adminHdr())
	if cw.Code != http.StatusOK {
		t.Fatalf("cancel = %d, want 200; body=%s", cw.Code, cw.Body.String())
	}
	var c alert.Alert
	if err := json.Unmarshal(cw.Body.Bytes(), &c); err != nil {
		t.Fatalf("decode cancel: %v", err)
	}
	if c.Type != "cancel" || c.Cancels != a.ID {
		t.Fatalf("cancel envelope = %+v, want type=cancel cancels=%s", c, a.ID)
	}
	if !alert.Verify(&c, ts.pub) {
		t.Fatal("cancel envelope must be signed and verify")
	}
}

func TestCancel_MissingID(t *testing.T) {
	ts := newTestServer(t)
	w := ts.req(t, http.MethodPost, "/api/cancel", cancelReq{ID: ""}, adminHdr())
	if w.Code != http.StatusBadRequest {
		t.Fatalf("cancel with empty id = %d, want 400", w.Code)
	}
}

// TestTenantIsolation is the multi-tenant guarantee: an alert published under one
// org must never appear in another org's history (SPEC/ARCHITECTURE multi-tenancy).
func TestTenantIsolation(t *testing.T) {
	ts := newTestServer(t)
	org2, err := ts.srv.Store.CreateOrg("acme", "Acme")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	org1 := ts.srv.DefaultOrgID

	pubTo := func(org int64, title string) {
		body := validPublish()
		body.Title = title
		h := adminHdr()
		h["X-Org-Id"] = itoa(org)
		if w := ts.req(t, http.MethodPost, "/api/publish", body, h); w.Code != http.StatusOK {
			t.Fatalf("publish to org %d = %d", org, w.Code)
		}
	}
	pubTo(org1, "org1-alert")
	pubTo(org2, "org2-alert")

	histOf := func(org int64) []alert.Alert {
		h := adminHdr()
		h["X-Org-Id"] = itoa(org)
		w := ts.req(t, http.MethodGet, "/api/history", nil, h)
		if w.Code != http.StatusOK {
			t.Fatalf("history org %d = %d", org, w.Code)
		}
		var out []alert.Alert
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	h1, h2 := histOf(org1), histOf(org2)
	if len(h1) != 1 || h1[0].Title != "org1-alert" {
		t.Fatalf("org1 history = %+v, want only org1-alert", h1)
	}
	if len(h2) != 1 || h2[0].Title != "org2-alert" {
		t.Fatalf("org2 history = %+v, want only org2-alert (leak = tenant isolation broken)", h2)
	}
}

func TestDevices_Auth(t *testing.T) {
	ts := newTestServer(t)
	if w := ts.req(t, http.MethodGet, "/api/devices", nil, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauth devices = %d, want 401", w.Code)
	}
	if w := ts.req(t, http.MethodGet, "/api/devices", nil, adminHdr()); w.Code != http.StatusOK {
		t.Fatalf("admin devices = %d, want 200", w.Code)
	}
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}

// --- P0 fail-loud: the server's self-check ---------------------------------

// TestSelfCheck_OKWhenHealthy is the baseline: a fully wired server reports ok.
func TestSelfCheck_OKWhenHealthy(t *testing.T) {
	ts := newTestServer(t)
	health, reason := ts.srv.selfCheck()
	if health != alert.HealthOK || reason != "" {
		t.Fatalf("healthy server reported %q (%s), want ok", health, reason)
	}
}

// TestSelfCheck_DegradedWhenStoreDown is the whole point of the feature: before
// it existed the beat was unconditionally green, so a server whose database had
// gone away still told every client it was fine.
func TestSelfCheck_DegradedWhenStoreDown(t *testing.T) {
	ts := newTestServer(t)
	if err := ts.srv.Store.Close(); err != nil { // simulate the DB going away
		t.Fatalf("close store: %v", err)
	}
	health, reason := ts.srv.selfCheck()
	if health != alert.HealthDegraded {
		t.Fatalf("store is down but self-check said %q — the beat would lie", health)
	}
	if reason == "" {
		t.Error("a degraded verdict must carry a reason for the server log")
	}
}

// TestSelfCheck_DegradedAfterPublishFailure covers the broker half: a failed
// publish is remembered and surfaced on the next beat.
func TestSelfCheck_DegradedAfterPublishFailure(t *testing.T) {
	ts := newTestServer(t)
	ts.srv.notePublishResult(errors.New("broker gone"))
	health, reason := ts.srv.selfCheck()
	if health != alert.HealthDegraded || !strings.Contains(reason, "broker gone") {
		t.Fatalf("after a publish failure: %q (%s), want degraded carrying the cause", health, reason)
	}
	// …and it clears once publishing works again.
	ts.srv.notePublishResult(nil)
	if health, _ := ts.srv.selfCheck(); health != alert.HealthOK {
		t.Fatalf("recovered server still reports %q", health)
	}
}

// TestRunHeartbeat_PublishesSignedBeatWithHealth drives the real loop for one
// beat and checks what actually lands on the broker topic.
func TestRunHeartbeat_PublishesSignedBeatWithHealth(t *testing.T) {
	ts := newTestServer(t)
	got := make(chan []byte, 4)
	if err := ts.srv.Broker.Subscribe(TopicHeartbeat, func(_ string, payload []byte) {
		select {
		case got <- payload:
		default:
		}
	}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ts.srv.RunHeartbeat(ctx) // emits one beat immediately

	select {
	case payload := <-got:
		var hb alert.Heartbeat
		if err := json.Unmarshal(payload, &hb); err != nil {
			t.Fatalf("decode heartbeat: %v", err)
		}
		if hb.Health != alert.HealthOK {
			t.Errorf("health = %q, want ok", hb.Health)
		}
		if hb.Interval != HeartbeatInterval || hb.Seq != 1 {
			t.Errorf("unexpected beat: %+v", hb)
		}
		if !alert.VerifyHeartbeat(&hb, ts.pub) {
			t.Error("published heartbeat does not verify against the server public key")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no heartbeat published within 5s")
	}
}
