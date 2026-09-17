package api

// Audit recording + the read/verify endpoints. Store-side design (hash chain,
// append-only) lives in store/audit.go.

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/KazuhaHub/AlertHub/server/internal/auth"
	"github.com/KazuhaHub/AlertHub/server/internal/store"
)

// Audit action names. Kept as constants so a typo cannot silently create a
// parallel action that nobody queries for.
const (
	AuditAlertPublish = "alert.publish"
	AuditAlertCancel  = "alert.cancel"
	AuditLogin        = "auth.login"
	AuditLoginFailed  = "auth.login_failed"
	AuditSACreate     = "service_account.create"
	AuditSADelete     = "service_account.delete"
	AuditOrgCreate    = "org.create"
	// Credential-lifecycle events. "who turned off 2FA on that account" and "who
	// added a passkey" are exactly the questions an incident review asks, and
	// they are also the classic account-takeover footprint.
	Audit2FAEnable    = "2fa.enable"
	Audit2FADisable   = "2fa.disable"
	AuditPasskeyAdd   = "passkey.add"
	AuditPasskeyDel   = "passkey.delete"
	AuditSSOLogin     = "auth.sso_login"
	AuditSSOProvision = "auth.sso_provision"
)

// actorOf derives who is acting from the request. The three authentication
// mechanisms produce three different kinds of actor, and an audit trail that
// cannot tell them apart is not much of an audit trail.
func (s *Server) actorOf(r *http.Request) (kind string, id int64, name string) {
	if c := claimsFrom(r); c != nil {
		return store.ActorUser, c.UserID, c.UPN
	}
	if v, ok := r.Context().Value(orgCtxKey).(int64); ok && v != 0 {
		// requireScope authenticated a service-account key for this org.
		return store.ActorServiceAccount, 0, "service-account"
	}
	return store.ActorAdminToken, 0, "admin-token"
}

// audit writes one entry, best-effort: a failure to record must never take down
// the action itself (refusing to broadcast an emergency because the audit table
// is unavailable would be a far worse outcome), but it is logged loudly.
func (s *Server) audit(r *http.Request, orgID int64, action, targetType, targetID, detail string) {
	kind, id, name := s.actorOf(r)
	e := &store.AuditEntry{
		OrgID: orgID, ActorType: kind, ActorID: id, ActorName: name,
		Action: action, TargetType: targetType, TargetID: targetID,
		Detail: detail, IP: clientIP(r),
	}
	if err := s.Store.AppendAudit(e); err != nil {
		slog.Error("audit append failed", "action", action, "org_id", orgID, "err", err)
	}
}

// auditSystem records an action with no HTTP request behind it (EEW, CAP feeds
// wired internally, background workers).
func (s *Server) auditSystem(orgID int64, action, targetType, targetID, detail string) {
	e := &store.AuditEntry{
		OrgID: orgID, ActorType: store.ActorSystem, ActorName: detail,
		Action: action, TargetType: targetType, TargetID: targetID, Detail: detail,
	}
	if err := s.Store.AppendAudit(e); err != nil {
		slog.Error("audit append failed", "action", action, "org_id", orgID, "err", err)
	}
}

// GET /api/audit?limit=N — the active org's trail, newest first.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	entries, err := s.Store.ListAudit(s.orgFor(r), limit)
	if err != nil {
		http.Error(w, "audit list failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, entries)
}

// GET /api/audit/verify — recompute the whole chain.
//
// The chain is global (it protects platform integrity), so verifying it reads
// across orgs. That makes this a super-admin operation, not something an org
// admin can run.
func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	if !s.isSuper(r) {
		http.Error(w, "super-admin only", http.StatusForbidden)
		return
	}
	res, err := s.Store.VerifyAuditChain()
	if err != nil {
		http.Error(w, "verify failed", http.StatusInternalServerError)
		return
	}
	if !res.OK {
		slog.Error("AUDIT CHAIN BROKEN", "bad_id", res.BadID, "reason", res.Reason, "entries", res.Entries)
	}
	writeJSON(w, res)
}

// auditPerm is the permission required to read the trail. Reading who fired an
// alert is an administrative capability, not something every viewer gets.
const auditPerm = auth.PermSettingsManage

// auditLoginAttempt records an authentication attempt. It cannot use actorOf:
// at login time there is no session yet, and on failure there may be no user at
// all — the attempted name is the only identity we have, and it is recorded as
// supplied (never the password).
func (s *Server) auditLoginAttempt(r *http.Request, upn string, ok bool) {
	action, detail := AuditLogin, "password"
	if !ok {
		action, detail = AuditLoginFailed, "password: invalid credentials"
	}
	e := &store.AuditEntry{
		OrgID: s.DefaultOrgID, ActorType: store.ActorUser, ActorName: upn,
		Action: action, TargetType: "user", TargetID: upn, Detail: detail, IP: clientIP(r),
	}
	if err := s.Store.AppendAudit(e); err != nil {
		slog.Error("audit append failed", "action", action, "err", err)
	}
}
