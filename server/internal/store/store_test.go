package store

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/KazuhaHub/AlertHub/server/internal/alert"
)

// These tests exercise the SQLite (Starter-tier) code path, which is what
// `go test ./...` runs by default. Before they existed the store package's only
// test file was pg_test.go — every case in it skips without ALERTHUB_TEST_PG_DSN,
// so the default gate covered this package with zero tests.

func openTestSQLite(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSQLite_OpenIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "twice.db")
	s1, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	_ = s1.Close()
	// Re-opening runs migrate() again over an existing schema; the additive
	// ALTERs must not turn that into an error.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("second Open (migrations must be idempotent): %v", err)
	}
	defer s2.Close()
	if s2.IsPostgres() {
		t.Error("sqlite store must not report IsPostgres")
	}
	if err := s2.Ping(); err != nil {
		t.Errorf("Ping: %v", err)
	}
}

// TestSQLite_BeginOrgIsNoOp pins the documented dialect difference: RLS is a
// Postgres feature, so on SQLite BeginOrg hands back the receiver and a nil tx
// (app-level org_id filters remain the isolation).
func TestSQLite_BeginOrgIsNoOp(t *testing.T) {
	s := openTestSQLite(t)
	got, tx, err := s.BeginOrg(context.Background(), 1)
	if err != nil {
		t.Fatalf("BeginOrg: %v", err)
	}
	if tx != nil {
		t.Error("sqlite BeginOrg must return a nil tx")
	}
	if got != s {
		t.Error("sqlite BeginOrg must return the receiver unchanged")
	}
}

func mkTestAlert(id, title string) *alert.Alert {
	return &alert.Alert{
		SchemaVersion: alert.SchemaVersion, ID: id, Type: "alert",
		Category: "system", Severity: "notice", Title: title, Source: "test",
		IssuedAt: 1765238400, TTL: 600, Nonce: "9f86d081884c7d659a2feaa0c55ad015",
	}
}

func TestSQLite_SaveHistoryOrgIsolation(t *testing.T) {
	s := openTestSQLite(t)
	def, err := s.EnsureDefaultOrg()
	if err != nil {
		t.Fatalf("EnsureDefaultOrg: %v", err)
	}
	acme, err := s.CreateOrg("acme", "Acme")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	if err := s.Save(mkTestAlert("a1", "default alert"), def); err != nil {
		t.Fatalf("Save default: %v", err)
	}
	if err := s.Save(mkTestAlert("a2", "acme alert"), acme); err != nil {
		t.Fatalf("Save acme: %v", err)
	}
	for _, tc := range []struct {
		org  int64
		want string
	}{{def, "default alert"}, {acme, "acme alert"}} {
		h, err := s.History(tc.org, 50)
		if err != nil {
			t.Fatalf("History(%d): %v", tc.org, err)
		}
		if len(h) != 1 {
			t.Fatalf("org %d: want 1 alert, got %d (tenant leak)", tc.org, len(h))
		}
		if !bytes.Contains(h[0], []byte(tc.want)) {
			t.Errorf("org %d: envelope %s does not contain %q", tc.org, h[0], tc.want)
		}
	}
}

// TestSQLite_SaveIsUpsert covers the ON CONFLICT(id) DO UPDATE path — the same
// alert id republished (e.g. an EEW renew) must update in place, not duplicate.
func TestSQLite_SaveIsUpsert(t *testing.T) {
	s := openTestSQLite(t)
	org, _ := s.EnsureDefaultOrg()
	_ = s.Save(mkTestAlert("same-id", "first"), org)
	if err := s.Save(mkTestAlert("same-id", "second"), org); err != nil {
		t.Fatalf("re-Save: %v", err)
	}
	h, _ := s.History(org, 50)
	if len(h) != 1 {
		t.Fatalf("want 1 row after upsert, got %d", len(h))
	}
	if !bytes.Contains(h[0], []byte("second")) {
		t.Errorf("upsert must keep the newest envelope, got %s", h[0])
	}
}

func TestSQLite_HistoryLimit(t *testing.T) {
	s := openTestSQLite(t)
	org, _ := s.EnsureDefaultOrg()
	for _, id := range []string{"h1", "h2", "h3"} {
		_ = s.Save(mkTestAlert(id, id), org)
	}
	h, err := s.History(org, 2)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(h) != 2 {
		t.Fatalf("limit not honoured: want 2, got %d", len(h))
	}
}

func TestSQLite_Users(t *testing.T) {
	s := openTestSQLite(t)
	n, err := s.CountUsers()
	if err != nil || n != 0 {
		t.Fatalf("fresh DB: CountUsers = %d, %v; want 0", n, err)
	}
	id, err := s.CreateUser(&User{UPN: "alice", Email: "a@x", PasswordHash: "h", Role: "admin", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	u, err := s.GetUserByUPN("alice")
	if err != nil {
		t.Fatalf("GetUserByUPN: %v", err)
	}
	if u.ID != id || u.Email != "a@x" || u.Role != "admin" || !u.Enabled || u.IsSuperadmin {
		t.Fatalf("round-trip mismatch: %+v", u)
	}
	if byID, err := s.GetUserByID(id); err != nil || byID.UPN != "alice" {
		t.Fatalf("GetUserByID = %+v, %v", byID, err)
	}
	// TokenVersion is the JWT revocation counter.
	if err := s.BumpTokenVersion(id); err != nil {
		t.Fatalf("BumpTokenVersion: %v", err)
	}
	if u, _ := s.GetUserByID(id); u.TokenVersion != 1 {
		t.Errorf("TokenVersion = %d, want 1", u.TokenVersion)
	}
	if err := s.MakeSuperadmin(id); err != nil {
		t.Fatalf("MakeSuperadmin: %v", err)
	}
	if u, _ := s.GetUserByID(id); !u.IsSuperadmin {
		t.Error("MakeSuperadmin did not stick")
	}
	if _, err := s.GetUserByUPN("nobody"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing user should be ErrNotFound, got %v", err)
	}
}

func TestSQLite_SSOUsers(t *testing.T) {
	s := openTestSQLite(t)
	id, err := s.CreateSSOUser("bob", "b@x", "oidc", "subject-123", "viewer")
	if err != nil {
		t.Fatalf("CreateSSOUser: %v", err)
	}
	u, err := s.GetUserBySSO("oidc", "subject-123")
	if err != nil {
		t.Fatalf("GetUserBySSO: %v", err)
	}
	if u.ID != id || u.Role != "viewer" || u.PasswordHash != "" {
		t.Fatalf("SSO user mismatch: %+v", u)
	}
	// The (provider, subject) pair is the identity — a different provider must miss.
	if _, err := s.GetUserBySSO("saml", "subject-123"); !errors.Is(err, ErrNotFound) {
		t.Errorf("same subject under another provider must not resolve, got %v", err)
	}
}

func TestSQLite_OrgsAndMemberships(t *testing.T) {
	s := openTestSQLite(t)
	def, err := s.EnsureDefaultOrg()
	if err != nil {
		t.Fatalf("EnsureDefaultOrg: %v", err)
	}
	if again, _ := s.EnsureDefaultOrg(); again != def {
		t.Error("EnsureDefaultOrg must be idempotent")
	}
	acme, _ := s.CreateOrg("acme", "Acme")
	if o, err := s.GetOrgBySlug("acme"); err != nil || o.ID != acme || o.Name != "Acme" {
		t.Fatalf("GetOrgBySlug = %+v, %v", o, err)
	}
	if orgs, _ := s.ListOrgs(); len(orgs) != 2 {
		t.Fatalf("ListOrgs = %d, want 2", len(orgs))
	}

	uid, _ := s.CreateUser(&User{UPN: "carol", Role: "user", Enabled: true})
	if _, ok := s.GetMembershipRole(acme, uid); ok {
		t.Error("no membership yet, must not resolve a role")
	}
	if err := s.AddMembership(acme, uid, "dispatcher"); err != nil {
		t.Fatalf("AddMembership: %v", err)
	}
	role, ok := s.GetMembershipRole(acme, uid)
	if !ok || role != "dispatcher" {
		t.Fatalf("GetMembershipRole = %q, %v; want dispatcher", role, ok)
	}
	// Membership is per-org: the same user has no role in the other org.
	if _, ok := s.GetMembershipRole(def, uid); ok {
		t.Error("membership must not leak across orgs")
	}
	if err := s.AddMembership(acme, uid, "viewer"); err != nil {
		t.Fatalf("duplicate AddMembership must be a no-op, got %v", err)
	}
	orgs, err := s.OrgsForUser(uid)
	if err != nil || len(orgs) != 1 || orgs[0].ID != acme {
		t.Fatalf("OrgsForUser = %+v, %v; want [acme]", orgs, err)
	}
}

// TestSQLite_Backfills covers the one-time migration to multi-tenancy: existing
// users get a membership and pre-tenancy rows get the default org.
func TestSQLite_Backfills(t *testing.T) {
	s := openTestSQLite(t)
	uid, _ := s.CreateUser(&User{UPN: "legacy", Role: "operator", Enabled: true})
	if _, err := s.exec(`INSERT INTO alerts (id, org_id, envelope) VALUES ('old', 0, '{}')`); err != nil {
		t.Fatalf("seed pre-tenancy row: %v", err)
	}
	org, _ := s.EnsureDefaultOrg()
	if err := s.BackfillMemberships(org); err != nil {
		t.Fatalf("BackfillMemberships: %v", err)
	}
	if role, ok := s.GetMembershipRole(org, uid); !ok || role != "operator" {
		t.Errorf("backfilled membership = %q, %v; want the user's own role", role, ok)
	}
	if err := s.BackfillOrgID(org); err != nil {
		t.Fatalf("BackfillOrgID: %v", err)
	}
	h, _ := s.History(org, 50)
	if len(h) != 1 {
		t.Errorf("pre-tenancy alert should now belong to the default org, got %d rows", len(h))
	}
}

func TestSQLite_ServiceAccounts(t *testing.T) {
	s := openTestSQLite(t)
	def, _ := s.EnsureDefaultOrg()
	acme, _ := s.CreateOrg("acme", "Acme")

	idA, err := s.CreateServiceAccount("ingest-a", "hash-a", "alerts:ingest", def)
	if err != nil {
		t.Fatalf("CreateServiceAccount: %v", err)
	}
	_, _ = s.CreateServiceAccount("ingest-b", "hash-b", "alerts:ingest", acme)

	// Lookup by token hash is org-agnostic ON PURPOSE: auth must resolve a key
	// before any org is known (this is why service_accounts is excluded from RLS).
	sa, err := s.GetServiceAccountByTokenHash("hash-b")
	if err != nil || sa.OrgID != acme || sa.Scopes != "alerts:ingest" || sa.Disabled {
		t.Fatalf("GetServiceAccountByTokenHash = %+v, %v", sa, err)
	}
	if err := s.TouchServiceAccount(sa.ID); err != nil {
		t.Errorf("TouchServiceAccount: %v", err)
	}
	if got, _ := s.GetServiceAccountByTokenHash("hash-b"); got.LastUsedAt == 0 {
		t.Error("TouchServiceAccount must stamp last_used_at")
	}

	// Listing IS org-scoped.
	if l, _ := s.ListServiceAccounts(def); len(l) != 1 || l[0].Name != "ingest-a" {
		t.Fatalf("ListServiceAccounts(default) = %+v, want only ingest-a", l)
	}

	// Cross-org delete must be a safe no-op (regression guard: this was a real bug).
	if err := s.DeleteServiceAccount(idA, acme); err != nil {
		t.Fatalf("cross-org delete should not error: %v", err)
	}
	if l, _ := s.ListServiceAccounts(def); len(l) != 1 {
		t.Fatal("SECURITY: a cross-org delete removed another org's service account")
	}
	if err := s.DeleteServiceAccount(idA, def); err != nil {
		t.Fatalf("same-org delete: %v", err)
	}
	if l, _ := s.ListServiceAccounts(def); len(l) != 0 {
		t.Fatalf("same-org delete failed, %d rows left", len(l))
	}
}

func TestSQLite_Passkeys(t *testing.T) {
	s := openTestSQLite(t)
	uid, _ := s.CreateUser(&User{UPN: "dave", Enabled: true})
	id, err := s.AddPasskey(&Passkey{
		UserID: uid, CredentialID: "cred-1", Credential: []byte(`{"id":"x"}`),
		SignCount: 1, Name: "YubiKey",
	})
	if err != nil {
		t.Fatalf("AddPasskey: %v", err)
	}
	list, err := s.ListPasskeys(uid)
	if err != nil || len(list) != 1 || list[0].Name != "YubiKey" {
		t.Fatalf("ListPasskeys = %+v, %v", list, err)
	}
	p, err := s.GetPasskeyByCredID("cred-1")
	if err != nil || p.UserID != uid || !bytes.Equal(p.Credential, []byte(`{"id":"x"}`)) {
		t.Fatalf("GetPasskeyByCredID = %+v, %v", p, err)
	}
	// The sign counter is the clone-detection signal; it must persist.
	if err := s.UpdatePasskeyUsage("cred-1", 42); err != nil {
		t.Fatalf("UpdatePasskeyUsage: %v", err)
	}
	if p, _ := s.GetPasskeyByCredID("cred-1"); p.SignCount != 42 || p.LastUsedAt == 0 {
		t.Errorf("usage update did not stick: %+v", p)
	}
	// Delete is user-scoped: another user must not be able to remove this key.
	other, _ := s.CreateUser(&User{UPN: "mallory", Enabled: true})
	_ = s.DeletePasskey(other, id)
	if l, _ := s.ListPasskeys(uid); len(l) != 1 {
		t.Fatal("SECURITY: a different user deleted someone else's passkey")
	}
	if err := s.DeletePasskey(uid, id); err != nil {
		t.Fatalf("DeletePasskey: %v", err)
	}
	if l, _ := s.ListPasskeys(uid); len(l) != 0 {
		t.Error("owner's delete did not remove the passkey")
	}
}

func TestSQLite_TOTP(t *testing.T) {
	s := openTestSQLite(t)
	uid, _ := s.CreateUser(&User{UPN: "erin", Enabled: true})
	if _, err := s.GetTOTP(uid); !errors.Is(err, ErrNotFound) {
		t.Errorf("no enrollment yet: want ErrNotFound, got %v", err)
	}
	secret := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	if err := s.UpsertTOTPPending(uid, secret); err != nil {
		t.Fatalf("UpsertTOTPPending: %v", err)
	}
	tp, err := s.GetTOTP(uid)
	if err != nil || !bytes.Equal(tp.SecretEnc, secret) || tp.Enabled {
		t.Fatalf("pending TOTP = %+v, %v; must be stored but NOT enabled", tp, err)
	}
	if err := s.EnableTOTP(uid, "hash1\nhash2"); err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}
	if tp, _ := s.GetTOTP(uid); !tp.Enabled || tp.Recovery != "hash1\nhash2" {
		t.Fatalf("enabled TOTP = %+v", tp)
	}
	// Burning a recovery code rewrites the remaining set.
	if err := s.SetTOTPRecovery(uid, "hash2"); err != nil {
		t.Fatalf("SetTOTPRecovery: %v", err)
	}
	if tp, _ := s.GetTOTP(uid); tp.Recovery != "hash2" {
		t.Errorf("recovery = %q, want hash2", tp.Recovery)
	}
	// Re-enrolling must clear the enabled flag and the old recovery codes.
	if err := s.UpsertTOTPPending(uid, []byte{0x01}); err != nil {
		t.Fatalf("re-enroll: %v", err)
	}
	if tp, _ := s.GetTOTP(uid); tp.Enabled || tp.Recovery != "" {
		t.Errorf("re-enrollment must reset enabled/recovery, got %+v", tp)
	}
	if err := s.DeleteTOTP(uid); err != nil {
		t.Fatalf("DeleteTOTP: %v", err)
	}
	if _, err := s.GetTOTP(uid); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete: want ErrNotFound, got %v", err)
	}
}

func TestSQLite_DeliveryOutbox(t *testing.T) {
	s := openTestSQLite(t)
	org, _ := s.EnsureDefaultOrg()
	job := DeliveryJob{
		OrgID: org, AlertID: "al-1", Channel: "webhook", Target: "https://x/hook",
		Payload: `{"id":"al-1"}`, Severity: "critical", MaxAttempts: 3,
	}
	ins, err := s.EnqueueDelivery(job, 1000)
	if err != nil || !ins {
		t.Fatalf("EnqueueDelivery = %v, %v; want inserted", ins, err)
	}
	// Idempotent on (alert_id, channel, target) — a retry of the publish path
	// must not double-send.
	if ins, err := s.EnqueueDelivery(job, 1000); err != nil || ins {
		t.Fatalf("duplicate enqueue = %v, %v; want not-inserted", ins, err)
	}

	// Nothing is due before next_attempt_at.
	if got, _ := s.ClaimDueDeliveries(999, 60, 10); len(got) != 0 {
		t.Fatalf("claimed %d jobs before they were due", len(got))
	}
	claimed, err := s.ClaimDueDeliveries(1000, 60, 10)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("ClaimDueDeliveries = %d, %v; want 1", len(claimed), err)
	}
	if claimed[0].Attempts != 1 || claimed[0].AlertID != "al-1" || claimed[0].MaxAttempts != 3 {
		t.Fatalf("claimed job = %+v", claimed[0])
	}
	// The claim leases the row: a second worker at the same instant sees nothing.
	if got, _ := s.ClaimDueDeliveries(1000, 60, 10); len(got) != 0 {
		t.Fatalf("lease not honoured: a second claim got %d jobs", len(got))
	}
	// After the lease expires it becomes claimable again (crash recovery).
	if got, _ := s.ClaimDueDeliveries(1061, 60, 10); len(got) != 1 {
		t.Fatal("expired lease must make the job claimable again")
	}

	id := claimed[0].ID
	if err := s.RescheduleDelivery(id, 2000, "boom", 1100); err != nil {
		t.Fatalf("RescheduleDelivery: %v", err)
	}
	if err := s.MarkDeliverySent(id, 1200); err != nil {
		t.Fatalf("MarkDeliverySent: %v", err)
	}
	counts, err := s.CountDeliveriesByStatus()
	if err != nil || counts["sent"] != 1 {
		t.Fatalf("CountDeliveriesByStatus = %v, %v", counts, err)
	}
	if oc, _ := s.DeliveryStatusCounts(org); oc["sent"] != 1 {
		t.Errorf("DeliveryStatusCounts(org) = %v", oc)
	}
}

func TestSQLite_DeliveryDeadLetter(t *testing.T) {
	s := openTestSQLite(t)
	org, _ := s.EnsureDefaultOrg()
	other, _ := s.CreateOrg("other", "Other")
	_, _ = s.EnqueueDelivery(DeliveryJob{
		OrgID: org, AlertID: "al-x", Channel: "email", Target: "a@x",
		Payload: "{}", Severity: "emergency", MaxAttempts: 1,
	}, 500)
	claimed, _ := s.ClaimDueDeliveries(500, 60, 10)
	if len(claimed) != 1 {
		t.Fatalf("setup: claimed %d", len(claimed))
	}
	if err := s.MarkDeliveryDead(claimed[0].ID, "gave up", 600); err != nil {
		t.Fatalf("MarkDeliveryDead: %v", err)
	}
	dead, err := s.RecentDeadDeliveries(org, 10)
	if err != nil || len(dead) != 1 {
		t.Fatalf("RecentDeadDeliveries = %+v, %v; want 1", dead, err)
	}
	if dead[0].AlertID != "al-x" || dead[0].Channel != "email" || dead[0].LastError != "gave up" {
		t.Errorf("dead letter = %+v", dead[0])
	}
	// Dead-letter visibility is org-scoped.
	if d, _ := s.RecentDeadDeliveries(other, 10); len(d) != 0 {
		t.Error("dead letters must not leak across orgs")
	}
}
