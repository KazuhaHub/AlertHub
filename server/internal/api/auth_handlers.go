package api

import (
	"encoding/json"
	"net/http"

	"github.com/KazuhaHub/AlertHub/server/internal/auth"
	"github.com/KazuhaHub/AlertHub/server/internal/metrics"
	"github.com/KazuhaHub/AlertHub/server/internal/store"
)

type userDTO struct {
	ID    int64  `json:"id"`
	UPN   string `json:"upn"`
	Role  string `json:"role"`
	Email string `json:"email,omitempty"`
}

func toDTO(u *store.User) userDTO {
	return userDTO{ID: u.ID, UPN: u.UPN, Role: u.Role, Email: u.Email}
}

type loginReq struct {
	UPN      string `json:"upn"`
	Password string `json:"password"`
}
type tokenResp struct {
	AccessToken  string  `json:"access_token"`
	RefreshToken string  `json:"refresh_token"`
	User         userDTO `json:"user"`
}

// POST /api/auth/login
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	u, err := s.Store.GetUserByUPN(req.UPN)
	if err != nil || u.PasswordHash == "" || !u.Enabled || !auth.CheckPassword(u.PasswordHash, req.Password) {
		metrics.Logins.WithLabelValues("password", "fail").Inc()
		// Failed logins are recorded with the attempted name but never the password;
		// a burst from one IP is exactly what this trail exists to surface.
		s.auditLoginAttempt(r, req.UPN, false)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	metrics.Logins.WithLabelValues("password", "success").Inc()
	s.auditLoginAttempt(r, u.UPN, true)
	// If 2FA is enrolled, password is only the first factor → return a pending token.
	if s.TwoFA != nil {
		if on, _ := s.TwoFA.Status(u.ID); on {
			pending, err := s.Auth.IssuePending(u.ID, u.UPN, u.Role, u.TokenVersion)
			if err != nil {
				http.Error(w, "token error", http.StatusInternalServerError)
				return
			}
			writeJSON(w, map[string]any{
				"status":        "2fa_required",
				"pending_token": pending,
				"methods":       []string{"totp", "recovery"},
			})
			return
		}
	}
	access, refresh, err := s.Auth.IssueTokens(u.ID, u.UPN, u.Role, u.TokenVersion)
	if err != nil {
		http.Error(w, "token error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, tokenResp{access, refresh, toDTO(u)})
}

type verify2FAReq struct {
	PendingToken string `json:"pending_token"`
	Code         string `json:"code"`
}

// POST /api/auth/2fa/verify — exchange a pending token + code for a full session.
func (s *Server) handle2FAVerify(w http.ResponseWriter, r *http.Request) {
	var req verify2FAReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	claims, err := s.Auth.Verify(req.PendingToken, auth.SubjectPending)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	u, err := s.Store.GetUserByID(claims.UserID)
	if err != nil || !u.Enabled || u.TokenVersion != claims.TokenVersion {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.TwoFA == nil {
		http.Error(w, "2fa not configured", http.StatusServiceUnavailable)
		return
	}
	if !s.TwoFA.VerifyLogin(u.ID, req.Code) {
		http.Error(w, "invalid code", http.StatusUnauthorized)
		return
	}
	access, refresh, err := s.Auth.IssueTokens(u.ID, u.UPN, u.Role, u.TokenVersion)
	if err != nil {
		http.Error(w, "token error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, tokenResp{access, refresh, toDTO(u)})
}

// GET /api/auth/2fa/status (session)
func (s *Server) handle2FAStatus(w http.ResponseWriter, r *http.Request) {
	c := claimsFrom(r)
	// A nil TwoFA means the feature was never wired; report "not enabled" rather
	// than panicking. handleLogin already treats nil the same way.
	if c == nil || s.TwoFA == nil {
		writeJSON(w, map[string]any{"enabled": false})
		return
	}
	on, _ := s.TwoFA.Status(c.UserID)
	writeJSON(w, map[string]any{"enabled": on})
}

// POST /api/auth/2fa/begin (session) — start TOTP enrollment.
func (s *Server) handle2FABegin(w http.ResponseWriter, r *http.Request) {
	c := claimsFrom(r)
	if c == nil {
		http.Error(w, "session required", http.StatusBadRequest)
		return
	}
	if s.TwoFA == nil {
		http.Error(w, "2fa not configured", http.StatusServiceUnavailable)
		return
	}
	u, err := s.Store.GetUserByID(c.UserID)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	url, secret, err := s.TwoFA.Begin(u.ID, u.UPN)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"otpauth_url": url, "secret": secret})
}

type codeReq struct {
	Code string `json:"code"`
}

// POST /api/auth/2fa/enable (session) {code} — confirm + enable, returns recovery codes.
func (s *Server) handle2FAEnable(w http.ResponseWriter, r *http.Request) {
	c := claimsFrom(r)
	if c == nil {
		http.Error(w, "session required", http.StatusBadRequest)
		return
	}
	if s.TwoFA == nil {
		http.Error(w, "2fa not configured", http.StatusServiceUnavailable)
		return
	}
	var req codeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	codes, err := s.TwoFA.Enable(c.UserID, req.Code)
	if err != nil {
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}
	s.audit(r, s.orgFor(r), Audit2FAEnable, "user", c.UPN, "TOTP enabled")
	writeJSON(w, map[string]any{"recovery_codes": codes})
}

// POST /api/auth/2fa/disable (session) {code}
func (s *Server) handle2FADisable(w http.ResponseWriter, r *http.Request) {
	c := claimsFrom(r)
	if c == nil {
		http.Error(w, "session required", http.StatusBadRequest)
		return
	}
	if s.TwoFA == nil {
		http.Error(w, "2fa not configured", http.StatusServiceUnavailable)
		return
	}
	var req codeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if err := s.TwoFA.Disable(c.UserID, req.Code); err != nil {
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}
	// Disabling a second factor weakens the account — always recorded.
	s.audit(r, s.orgFor(r), Audit2FADisable, "user", c.UPN, "TOTP disabled")
	w.WriteHeader(http.StatusNoContent)
}

type refreshReq struct {
	RefreshToken string `json:"refresh_token"`
}

// POST /api/auth/refresh
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req refreshReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	claims, err := s.Auth.Verify(req.RefreshToken, auth.SubjectRefresh)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	u, err := s.Store.GetUserByID(claims.UserID)
	if err != nil || !u.Enabled || u.TokenVersion != claims.TokenVersion {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	access, refresh, err := s.Auth.IssueTokens(u.ID, u.UPN, u.Role, u.TokenVersion)
	if err != nil {
		http.Error(w, "token error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, tokenResp{access, refresh, toDTO(u)})
}

// GET /api/auth/methods — drives the login UI (which methods to show).
func (s *Server) handleAuthMethods(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"local":                true,
		"passkey_enabled":      s.Passkey != nil,
		"passkey_passwordless": s.Passkey != nil,
		"sso":                  (s.OIDC != nil && s.OIDC.Enabled()) || (s.SAML != nil && s.SAML.Enabled()),
		"oidc":                 s.OIDC != nil && s.OIDC.Enabled(),
		"saml":                 s.SAML != nil && s.SAML.Enabled(),
		"site_title":           "AlertHub 控制台",
	})
}

// GET /api/auth/me
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	c := claimsFrom(r)
	if c == nil { // reached via admin-token fallback (no JWT claims)
		writeJSON(w, userDTO{UPN: "admin-token", Role: "admin"})
		return
	}
	u, err := s.Store.GetUserByID(c.UserID)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, toDTO(u))
}

// POST /api/auth/logout — stateless; client drops tokens. Clears the cookie if set.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "ah_access", Value: "", Path: "/", MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}
