package store

import (
	"os"
	"testing"

	"github.com/KazuhaHub/AlertHub/server/internal/alert"
)

// These tests run only when ALERTHUB_TEST_PG_DSN points at a disposable Postgres
// (e.g. "postgres://user@localhost:5432/alerthub_test?sslmode=disable"). Without
// it they skip, so the default `go test ./...` stays green on machines with no PG.
func openTestPG(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("ALERTHUB_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("set ALERTHUB_TEST_PG_DSN to run Postgres integration tests")
	}
	s, err := OpenPostgres(dsn)
	if err != nil {
		t.Fatalf("OpenPostgres: %v", err)
	}
	// Fresh slate (superuser bypasses RLS, so TRUNCATE is fine).
	if _, err := s.db.Exec(
		`TRUNCATE alerts, orgs, users, memberships, service_accounts RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return s
}

func mkAlert(id, title string) *alert.Alert {
	return &alert.Alert{ID: id, Type: "alert", Category: "system", Severity: "notice", Title: title}
}

// The same multi-tenant behaviour the app relies on, exercised against real
// Postgres: org-scoped Save/History isolation + BIGSERIAL id generation.
func TestPostgres_TenantIsolation(t *testing.T) {
	s := openTestPG(t)
	defer s.Close()

	def, err := s.EnsureDefaultOrg()
	if err != nil {
		t.Fatalf("EnsureDefaultOrg: %v", err)
	}
	acme, err := s.CreateOrg("acme", "Acme")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	if acme <= def {
		t.Fatalf("expected BIGSERIAL ids to advance, got default=%d acme=%d", def, acme)
	}

	if err := s.Save(mkAlert("a-default", "default alert"), def); err != nil {
		t.Fatalf("Save default: %v", err)
	}
	if err := s.Save(mkAlert("a-acme", "acme alert"), acme); err != nil {
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
			t.Fatalf("org %d: want 1 alert, got %d", tc.org, len(h))
		}
		if got := string(h[0]); !contains(got, tc.want) {
			t.Fatalf("org %d: want %q in envelope, got %s", tc.org, tc.want, got)
		}
	}
}

// RLS proof: a non-superuser role sees ONLY the rows of the org named by the
// session GUC app.current_org — even with a bare `SELECT * FROM alerts` that has
// no WHERE clause. Unset GUC → zero rows (fail-closed). This is the defense-in-depth
// wall under the app-level org filters.
func TestPostgres_RLS(t *testing.T) {
	s := openTestPG(t)
	defer s.Close()

	def, _ := s.EnsureDefaultOrg()
	acme, _ := s.CreateOrg("acme", "Acme")
	_ = s.Save(mkAlert("a-default", "default alert"), def)
	_ = s.Save(mkAlert("a-acme", "acme alert"), acme)

	// A least-privilege role: NOSUPERUSER (and not BYPASSRLS) so policies apply.
	for _, q := range []string{
		`DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='alerthub_rls_test')
		 THEN CREATE ROLE alerthub_rls_test NOLOGIN NOSUPERUSER NOBYPASSRLS; END IF; END $$`,
		`GRANT SELECT ON alerts TO alerthub_rls_test`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatalf("role setup %q: %v", q, err)
		}
	}

	// Run everything on a single pinned connection (SET ROLE / SET are session state).
	conn, err := s.db.Conn(t.Context())
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(t.Context(), `SET ROLE alerthub_rls_test`); err != nil {
		t.Fatalf("set role: %v", err)
	}

	count := func() int {
		var n int
		// Deliberately no WHERE org_id — RLS must do the filtering.
		if err := conn.QueryRowContext(t.Context(), `SELECT count(*) FROM alerts`).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}

	// GUC unset → fail-closed.
	if _, err := conn.ExecContext(t.Context(), `RESET app.current_org`); err != nil {
		t.Fatalf("reset guc: %v", err)
	}
	if got := count(); got != 0 {
		t.Fatalf("unset GUC: want 0 rows (fail-closed), got %d", got)
	}

	for _, tc := range []struct {
		org  int64
		want int
	}{{def, 1}, {acme, 1}} {
		if _, err := conn.ExecContext(t.Context(),
			`SELECT set_config('app.current_org', $1, false)`, itoa(tc.org)); err != nil {
			t.Fatalf("set guc: %v", err)
		}
		if got := count(); got != tc.want {
			t.Fatalf("org %d: RLS want %d rows, got %d", tc.org, tc.want, got)
		}
	}

	// A non-existent org sees nothing.
	if _, err := conn.ExecContext(t.Context(),
		`SELECT set_config('app.current_org', '99999', false)`); err != nil {
		t.Fatalf("set guc: %v", err)
	}
	if got := count(); got != 0 {
		t.Fatalf("bogus org: want 0 rows, got %d", got)
	}
}

// TestPostgres_BeginOrg_SetsGUC proves the wiring: BeginOrg opens a tx with the
// transaction-local GUC app.current_org set to the org, and the returned tx-bound
// Store runs its queries inside that tx.
func TestPostgres_BeginOrg_SetsGUC(t *testing.T) {
	s := openTestPG(t)
	defer s.Close()

	def, _ := s.EnsureDefaultOrg()
	acme, _ := s.CreateOrg("acme", "Acme")
	_ = s.Save(mkAlert("a-default", "default alert"), def)
	_ = s.Save(mkAlert("a-acme", "acme alert"), acme)

	st, tx, err := s.BeginOrg(t.Context(), acme)
	if err != nil {
		t.Fatalf("BeginOrg: %v", err)
	}
	defer tx.Rollback()

	var guc string
	if err := tx.QueryRowContext(t.Context(),
		`SELECT current_setting('app.current_org', true)`).Scan(&guc); err != nil {
		t.Fatalf("read guc: %v", err)
	}
	if guc != itoa(acme) {
		t.Fatalf("app.current_org = %q, want %q", guc, itoa(acme))
	}
	// The tx-bound Store must run History inside this same tx.
	h, err := st.History(acme, 50)
	if err != nil {
		t.Fatalf("tx-store History: %v", err)
	}
	if len(h) != 1 || !contains(string(h[0]), "acme alert") {
		t.Fatalf("tx-store History = %v, want [acme alert]", h)
	}
}

// TestPostgres_RLS_LiveViaBeginOrg is the end-to-end proof that RLS is now the LIVE
// enforcement layer through the wired path: under a least-privilege role, a bare
// `SELECT * FROM alerts` inside a BeginOrg(org) transaction returns only that org's
// rows — no explicit WHERE, RLS does the filtering off the GUC that BeginOrg set.
func TestPostgres_RLS_LiveViaBeginOrg(t *testing.T) {
	s := openTestPG(t)
	defer s.Close()

	def, _ := s.EnsureDefaultOrg()
	acme, _ := s.CreateOrg("acme", "Acme")
	_ = s.Save(mkAlert("a-default", "default alert"), def)
	_ = s.Save(mkAlert("a-acme", "acme alert"), acme)

	for _, q := range []string{
		`DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='alerthub_rls_test')
		 THEN CREATE ROLE alerthub_rls_test NOLOGIN NOSUPERUSER NOBYPASSRLS; END IF; END $$`,
		`GRANT SELECT, INSERT ON alerts TO alerthub_rls_test`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatalf("role setup %q: %v", q, err)
		}
	}

	for _, tc := range []struct {
		org  int64
		want int
	}{{def, 1}, {acme, 1}} {
		st, tx, err := s.BeginOrg(t.Context(), tc.org)
		if err != nil {
			t.Fatalf("BeginOrg: %v", err)
		}
		// Downgrade to the least-priv role inside the same tx so RLS is enforced;
		// the GUC set by BeginOrg is transaction state and survives the role switch.
		if _, err := tx.ExecContext(t.Context(), `SET LOCAL ROLE alerthub_rls_test`); err != nil {
			tx.Rollback()
			t.Fatalf("set role: %v", err)
		}
		var n int
		// Deliberately no WHERE org_id — RLS must filter to the GUC's org.
		if err := tx.QueryRowContext(t.Context(), `SELECT count(*) FROM alerts`).Scan(&n); err != nil {
			tx.Rollback()
			t.Fatalf("count: %v", err)
		}
		if n != tc.want {
			tx.Rollback()
			t.Fatalf("org %d: RLS-live bare SELECT saw %d rows, want %d", tc.org, n, tc.want)
		}
		_ = st
		tx.Rollback()
	}
}

// TestPostgres_RLS_WriteCheck proves the write-side wall: under a least-priv role,
// an INSERT whose org_id matches the BeginOrg GUC succeeds, but one whose org_id
// differs from the GUC is rejected by the policy's WITH CHECK — so a buggy or
// compromised path cannot write into another tenant even if it passes a wrong org_id.
func TestPostgres_RLS_WriteCheck(t *testing.T) {
	s := openTestPG(t)
	defer s.Close()

	def, _ := s.EnsureDefaultOrg()
	acme, _ := s.CreateOrg("acme", "Acme")
	for _, q := range []string{
		`DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='alerthub_rls_test')
		 THEN CREATE ROLE alerthub_rls_test NOLOGIN NOSUPERUSER NOBYPASSRLS; END IF; END $$`,
		`GRANT SELECT, INSERT, UPDATE ON alerts TO alerthub_rls_test`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatalf("role setup %q: %v", q, err)
		}
	}

	// Matching org → WITH CHECK passes.
	st, tx, err := s.BeginOrg(t.Context(), def)
	if err != nil {
		t.Fatalf("BeginOrg: %v", err)
	}
	if _, err := tx.ExecContext(t.Context(), `SET LOCAL ROLE alerthub_rls_test`); err != nil {
		tx.Rollback()
		t.Fatalf("set role: %v", err)
	}
	if err := st.Save(mkAlert("w-ok", "ok"), def); err != nil {
		tx.Rollback()
		t.Fatalf("Save with org == GUC must succeed under RLS, got: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Mismatched org (GUC=def, row org_id=acme) → WITH CHECK rejects.
	st2, tx2, err := s.BeginOrg(t.Context(), def)
	if err != nil {
		t.Fatalf("BeginOrg: %v", err)
	}
	defer tx2.Rollback()
	if _, err := tx2.ExecContext(t.Context(), `SET LOCAL ROLE alerthub_rls_test`); err != nil {
		t.Fatalf("set role: %v", err)
	}
	if err := st2.Save(mkAlert("w-bad", "bad"), acme); err == nil {
		t.Fatal("SECURITY: Save with org_id != GUC must be rejected by RLS WITH CHECK, but it succeeded")
	}
}

// TestPostgres_ServiceAccountsNotRLS asserts the deliberate design decision: the
// auth table service_accounts must NOT be under RLS (requireScope looks a key up
// by token_hash before any org is known), while alerts must be.
func TestPostgres_ServiceAccountsNotRLS(t *testing.T) {
	s := openTestPG(t)
	defer s.Close()

	var saEnabled, saForce bool
	if err := s.db.QueryRow(
		`SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname='service_accounts'`).
		Scan(&saEnabled, &saForce); err != nil {
		t.Fatalf("catalog service_accounts: %v", err)
	}
	if saEnabled || saForce {
		t.Fatalf("service_accounts must NOT have RLS (auth lookup precedes org); enabled=%v force=%v", saEnabled, saForce)
	}
	var alertsEnabled bool
	if err := s.db.QueryRow(
		`SELECT relrowsecurity FROM pg_class WHERE relname='alerts'`).Scan(&alertsEnabled); err != nil {
		t.Fatalf("catalog alerts: %v", err)
	}
	if !alertsEnabled {
		t.Fatal("alerts must have RLS enabled")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
