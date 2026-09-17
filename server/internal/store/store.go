// Package store persists AlertHub's data. It speaks two SQL dialects behind one
// code path: SQLite (modernc.org/sqlite, pure-Go, the single-binary/Starter tier)
// and PostgreSQL (jackc/pgx, the Enterprise tier — multi-tenant, RLS-capable).
// The only dialect differences are the DDL and the `?`→`$n` placeholder style;
// everything else uses portable SQL (RETURNING id, ON CONFLICT) that both engines
// support, routed through the rebind()/exec()/query() helpers below.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"

	"github.com/KazuhaHub/AlertHub/server/internal/alert"
	_ "github.com/jackc/pgx/v5/stdlib" // "pgx" driver (PostgreSQL)
	_ "modernc.org/sqlite"             // "sqlite" driver (pure Go)
)

// execer is the subset of *sql.DB and *sql.Tx that the query wrappers use. A
// plain Store runs on the *sql.DB (pooled); a request-scoped Store from BeginOrg
// runs on a *sql.Tx that has already SET LOCAL app.current_org, so RLS applies.
type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

type Store struct {
	db     *sql.DB // pool: DDL, Ping, Close, BeginOrg live here
	ex     execer  // where wrapped queries run: db by default, or a per-request tx
	driver string  // "sqlite" | "postgres"
	// auditMu serialises read-head-then-append on the audit hash chain. It is a
	// POINTER so the tx-bound clone from BeginOrg shares the same lock — a copied
	// mutex would let two writers chain onto the same predecessor and fork it.
	auditMu *sync.Mutex
}

func isNoRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }

// Open opens (or creates) the SQLite database at path — the single-binary tier.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, driver: "sqlite", auditMu: &sync.Mutex{}}
	s.ex = db
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// OpenPostgres opens a PostgreSQL database (dsn, e.g.
// "postgres://user:pass@host:5432/db?sslmode=disable") — the Enterprise tier.
func OpenPostgres(dsn string) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{db: db, driver: "postgres", auditMu: &sync.Mutex{}}
	s.ex = db
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// IsPostgres reports the active dialect (RLS wiring is Postgres-only).
func (s *Store) IsPostgres() bool { return s.driver == "postgres" }

func (s *Store) Close() error { return s.db.Close() }
func (s *Store) Ping() error  { return s.db.Ping() }

// rebind rewrites positional `?` placeholders to PostgreSQL's `$1,$2,…`. SQLite
// keeps `?` unchanged.
func (s *Store) rebind(q string) string {
	if s.driver != "postgres" {
		return q
	}
	var b strings.Builder
	b.Grow(len(q) + 8)
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
		} else {
			b.WriteByte(q[i])
		}
	}
	return b.String()
}

func (s *Store) exec(q string, args ...any) (sql.Result, error) {
	return s.ex.Exec(s.rebind(q), args...)
}
func (s *Store) query(q string, args ...any) (*sql.Rows, error) {
	return s.ex.Query(s.rebind(q), args...)
}
func (s *Store) queryRow(q string, args ...any) *sql.Row {
	return s.ex.QueryRow(s.rebind(q), args...)
}

// BeginOrg starts a request-scoped transaction bound to orgID and returns a Store
// view whose wrapped queries all run inside it. On Postgres it sets the
// transaction-local GUC app.current_org (SET LOCAL semantics via set_config's
// is_local=true), so the RLS policy from applyRLS filters every alerts query to
// this org — making RLS the LIVE enforcement wall, not just a latent one. Because
// it is transaction-local, a pooled connection never leaks one request's org to
// the next. On SQLite (no RLS) it is a no-op: it returns the receiver and a nil
// tx, and the app-level org_id filters remain the isolation.
//
// Callers must Commit or Rollback the returned tx when it is non-nil;
// api.Server.inOrg wraps this. The returned *Store must not outlive the tx.
func (s *Store) BeginOrg(ctx context.Context, orgID int64) (*Store, *sql.Tx, error) {
	if s.driver != "postgres" {
		return s, nil, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	if _, err := tx.ExecContext(ctx,
		`SELECT set_config('app.current_org', $1, true)`, strconv.FormatInt(orgID, 10)); err != nil {
		_ = tx.Rollback()
		return nil, nil, err
	}
	return &Store{db: s.db, ex: tx, driver: s.driver, auditMu: s.auditMu}, tx, nil
}

// insertID runs an INSERT and returns the generated id portably. RETURNING is
// supported by both modernc-sqlite (≥3.35) and PostgreSQL; lib/pq-style drivers
// have no LastInsertId(), so we never rely on it.
func (s *Store) insertID(q string, args ...any) (int64, error) {
	var id int64
	err := s.queryRow(q+" RETURNING id", args...).Scan(&id)
	return id, err
}

// migrate creates the schema for the active dialect (idempotent).
func (s *Store) migrate() error {
	if s.driver == "postgres" {
		return s.migratePostgres()
	}
	return s.migrateSQLite()
}

func (s *Store) migrateSQLite() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS alerts (
			id TEXT PRIMARY KEY, type TEXT, category TEXT, severity TEXT,
			title TEXT, body TEXT, action TEXT, source TEXT,
			issued_at INTEGER, ttl INTEGER, cancels TEXT, envelope TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			upn TEXT UNIQUE NOT NULL, email TEXT, password_hash TEXT,
			role TEXT NOT NULL DEFAULT 'user',
			enabled INTEGER NOT NULL DEFAULT 1,
			token_version INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS passkey_credentials (
			id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
			credential_id TEXT UNIQUE NOT NULL, credential BLOB NOT NULL,
			sign_count INTEGER NOT NULL DEFAULT 0, name TEXT,
			created_at INTEGER, last_used_at INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS user_totp (
			user_id INTEGER PRIMARY KEY, secret_enc BLOB,
			recovery TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS service_accounts (
			id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
			token_hash TEXT UNIQUE NOT NULL, scopes TEXT NOT NULL DEFAULT '',
			disabled INTEGER NOT NULL DEFAULT 0, created_at INTEGER, last_used_at INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS orgs (
			id INTEGER PRIMARY KEY AUTOINCREMENT, slug TEXT UNIQUE NOT NULL,
			name TEXT NOT NULL, created_at INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS memberships (
			org_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
			base_role TEXT NOT NULL DEFAULT 'user', created_at INTEGER,
			PRIMARY KEY (org_id, user_id)
		)`,
		`CREATE TABLE IF NOT EXISTS delivery_jobs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			org_id INTEGER NOT NULL, alert_id TEXT NOT NULL,
			channel TEXT NOT NULL, target TEXT NOT NULL,
			payload TEXT NOT NULL, severity TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			attempts INTEGER NOT NULL DEFAULT 0,
			max_attempts INTEGER NOT NULL DEFAULT 6,
			next_attempt_at INTEGER NOT NULL DEFAULT 0,
			last_error TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL DEFAULT 0,
			updated_at INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			org_id INTEGER NOT NULL, at INTEGER NOT NULL,
			actor_type TEXT NOT NULL, actor_id INTEGER NOT NULL DEFAULT 0,
			actor_name TEXT NOT NULL DEFAULT '', action TEXT NOT NULL,
			target_type TEXT NOT NULL DEFAULT '', target_id TEXT NOT NULL DEFAULT '',
			detail TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '',
			prev_hash TEXT NOT NULL DEFAULT '', hash TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS audit_log_org ON audit_log(org_id, id)`,
		`CREATE TABLE IF NOT EXISTS alert_acks (
			org_id INTEGER NOT NULL, alert_id TEXT NOT NULL, device_id TEXT NOT NULL,
			ack_at INTEGER NOT NULL, by_who TEXT NOT NULL DEFAULT '',
			PRIMARY KEY (alert_id, device_id)
		)`,
		`CREATE TABLE IF NOT EXISTS drills (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			org_id INTEGER NOT NULL, at INTEGER NOT NULL, alert_id TEXT NOT NULL,
			severity TEXT NOT NULL DEFAULT '', expected INTEGER NOT NULL DEFAULT 0,
			acked INTEGER NOT NULL DEFAULT 0, missed TEXT NOT NULL DEFAULT '',
			passed INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS settings (
			k TEXT PRIMARY KEY, v TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS cursors (
			name TEXT PRIMARY KEY, position INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS delivery_jobs_uniq ON delivery_jobs(alert_id, channel, target)`,
		`CREATE INDEX IF NOT EXISTS delivery_jobs_claim ON delivery_jobs(status, next_attempt_at)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	// Additive migrations for pre-existing DBs (errors ignored = column exists).
	s.db.Exec(`ALTER TABLE users ADD COLUMN sso_provider TEXT NOT NULL DEFAULT ''`)
	s.db.Exec(`ALTER TABLE users ADD COLUMN sso_subject TEXT NOT NULL DEFAULT ''`)
	s.db.Exec(`ALTER TABLE users ADD COLUMN is_superadmin INTEGER NOT NULL DEFAULT 0`)
	s.db.Exec(`ALTER TABLE alerts ADD COLUMN org_id INTEGER NOT NULL DEFAULT 0`)
	s.db.Exec(`ALTER TABLE service_accounts ADD COLUMN org_id INTEGER NOT NULL DEFAULT 0`)
	return nil
}

func (s *Store) migratePostgres() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS alerts (
			id TEXT PRIMARY KEY, type TEXT, category TEXT, severity TEXT,
			title TEXT, body TEXT, action TEXT, source TEXT,
			issued_at BIGINT, ttl BIGINT, cancels TEXT, envelope TEXT,
			org_id BIGINT NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS users (
			id BIGSERIAL PRIMARY KEY,
			upn TEXT UNIQUE NOT NULL, email TEXT, password_hash TEXT,
			role TEXT NOT NULL DEFAULT 'user',
			enabled INTEGER NOT NULL DEFAULT 1,
			token_version INTEGER NOT NULL DEFAULT 0,
			created_at BIGINT,
			sso_provider TEXT NOT NULL DEFAULT '',
			sso_subject TEXT NOT NULL DEFAULT '',
			is_superadmin INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS passkey_credentials (
			id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL,
			credential_id TEXT UNIQUE NOT NULL, credential BYTEA NOT NULL,
			sign_count BIGINT NOT NULL DEFAULT 0, name TEXT,
			created_at BIGINT, last_used_at BIGINT
		)`,
		`CREATE TABLE IF NOT EXISTS user_totp (
			user_id BIGINT PRIMARY KEY, secret_enc BYTEA,
			recovery TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS service_accounts (
			id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL,
			token_hash TEXT UNIQUE NOT NULL, scopes TEXT NOT NULL DEFAULT '',
			disabled INTEGER NOT NULL DEFAULT 0, created_at BIGINT, last_used_at BIGINT,
			org_id BIGINT NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS orgs (
			id BIGSERIAL PRIMARY KEY, slug TEXT UNIQUE NOT NULL,
			name TEXT NOT NULL, created_at BIGINT
		)`,
		`CREATE TABLE IF NOT EXISTS memberships (
			org_id BIGINT NOT NULL, user_id BIGINT NOT NULL,
			base_role TEXT NOT NULL DEFAULT 'user', created_at BIGINT,
			PRIMARY KEY (org_id, user_id)
		)`,
		`CREATE TABLE IF NOT EXISTS delivery_jobs (
			id BIGSERIAL PRIMARY KEY,
			org_id BIGINT NOT NULL, alert_id TEXT NOT NULL,
			channel TEXT NOT NULL, target TEXT NOT NULL,
			payload TEXT NOT NULL, severity TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			attempts INTEGER NOT NULL DEFAULT 0,
			max_attempts INTEGER NOT NULL DEFAULT 6,
			next_attempt_at BIGINT NOT NULL DEFAULT 0,
			last_error TEXT NOT NULL DEFAULT '',
			created_at BIGINT NOT NULL DEFAULT 0,
			updated_at BIGINT NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			id BIGSERIAL PRIMARY KEY,
			org_id BIGINT NOT NULL, at BIGINT NOT NULL,
			actor_type TEXT NOT NULL, actor_id BIGINT NOT NULL DEFAULT 0,
			actor_name TEXT NOT NULL DEFAULT '', action TEXT NOT NULL,
			target_type TEXT NOT NULL DEFAULT '', target_id TEXT NOT NULL DEFAULT '',
			detail TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '',
			prev_hash TEXT NOT NULL DEFAULT '', hash TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS audit_log_org ON audit_log(org_id, id)`,
		`CREATE TABLE IF NOT EXISTS alert_acks (
			org_id BIGINT NOT NULL, alert_id TEXT NOT NULL, device_id TEXT NOT NULL,
			ack_at BIGINT NOT NULL, by_who TEXT NOT NULL DEFAULT '',
			PRIMARY KEY (alert_id, device_id)
		)`,
		`CREATE TABLE IF NOT EXISTS drills (
			id BIGSERIAL PRIMARY KEY,
			org_id BIGINT NOT NULL, at BIGINT NOT NULL, alert_id TEXT NOT NULL,
			severity TEXT NOT NULL DEFAULT '', expected INTEGER NOT NULL DEFAULT 0,
			acked INTEGER NOT NULL DEFAULT 0, missed TEXT NOT NULL DEFAULT '',
			passed INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS settings (
			k TEXT PRIMARY KEY, v TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS cursors (
			name TEXT PRIMARY KEY, position BIGINT NOT NULL DEFAULT 0
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS delivery_jobs_uniq ON delivery_jobs(alert_id, channel, target)`,
		`CREATE INDEX IF NOT EXISTS delivery_jobs_claim ON delivery_jobs(status, next_attempt_at)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	// NB: delivery_jobs intentionally has NO RLS — it is the platform's internal
	// work queue; the worker claims across all orgs. RLS guards tenant-facing data
	// (alerts, service_accounts) only.
	return s.applyRLS()
}

// applyRLS installs Row-Level Security on the tenant DATA table (alerts) as
// defense-in-depth. Primary isolation is the app's explicit org_id filters
// (verified on both dialects); RLS is a second wall that holds even if a query
// ever forgets its WHERE. The policy keys off the per-transaction GUC
// `app.current_org` (set by BeginOrg); unset → NULL → zero rows (fail-closed).
// FORCE makes it apply to the table owner too, but a SUPERUSER connection always
// bypasses RLS — so to actually activate this wall, deploy with a least-privilege
// role (see docs/POSTGRES.md); the per-request SET LOCAL is now wired via
// Store.BeginOrg. Idempotent (safe to run every boot).
//
// service_accounts is deliberately NOT under RLS: requireScope must look a key up
// by token_hash BEFORE any org is known (auth is a chicken-and-egg lookup that
// cannot be org-gated), so an org-scoped policy there would break API-key auth.
// Its tenant isolation is the app-level org_id filter on create/list/delete.
func (s *Store) applyRLS() error {
	// NULLIF(...,'') so an unset OR empty GUC collapses to NULL → zero rows
	// (fail-closed); a custom placeholder GUC reads back as '' after RESET, not NULL.
	const guc = `NULLIF(current_setting('app.current_org', true), '')::bigint`
	stmts := []string{
		`ALTER TABLE alerts ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE alerts FORCE ROW LEVEL SECURITY`,
		`DROP POLICY IF EXISTS org_isolation ON alerts`,
		`CREATE POLICY org_isolation ON alerts` +
			` USING (org_id = ` + guc + `) WITH CHECK (org_id = ` + guc + `)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	// Remove any service_accounts policy left by an earlier build (best-effort:
	// harmless if it was never installed). See the doc comment above for why.
	for _, q := range []string{
		`DROP POLICY IF EXISTS org_isolation ON service_accounts`,
		`ALTER TABLE service_accounts NO FORCE ROW LEVEL SECURITY`,
		`ALTER TABLE service_accounts DISABLE ROW LEVEL SECURITY`,
	} {
		_, _ = s.db.Exec(q)
	}
	return nil
}

// Save records the full signed envelope, scoped to an org (upsert by id).
func (s *Store) Save(a *alert.Alert, orgID int64) error {
	env, err := json.Marshal(a)
	if err != nil {
		return err
	}
	_, err = s.exec(
		`INSERT INTO alerts
		 (id,type,category,severity,title,body,action,source,issued_at,ttl,cancels,envelope,org_id)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
		   type=excluded.type, category=excluded.category, severity=excluded.severity,
		   title=excluded.title, body=excluded.body, action=excluded.action,
		   source=excluded.source, issued_at=excluded.issued_at, ttl=excluded.ttl,
		   cancels=excluded.cancels, envelope=excluded.envelope, org_id=excluded.org_id`,
		a.ID, a.Type, a.Category, a.Severity, a.Title, a.Body, a.Action,
		a.Source, a.IssuedAt, a.TTL, a.Cancels, string(env), orgID,
	)
	return err
}

// History returns the most recent envelopes for an org, newest first.
func (s *Store) History(orgID int64, limit int) ([]json.RawMessage, error) {
	rows, err := s.query(
		`SELECT envelope FROM alerts WHERE org_id = ? ORDER BY issued_at DESC, id DESC LIMIT ?`, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var env string
		if err := rows.Scan(&env); err != nil {
			return nil, err
		}
		out = append(out, json.RawMessage(env))
	}
	return out, rows.Err()
}
