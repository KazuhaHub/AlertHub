package api

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"

	"github.com/KazuhaHub/AlertHub/server/internal/metrics"
	"github.com/KazuhaHub/AlertHub/server/internal/sso"
	"github.com/KazuhaHub/AlertHub/server/internal/store"
)

// One-time SSO bridge: the callback issues tokens, stashes them under a one-time
// code, and redirects the browser to /admin/sso?code=… ; the SPA exchanges the
// code (POST) for the tokens to store in localStorage. Avoids tokens in the URL
// fragment and the HttpOnly-cookie vs localStorage mismatch.
type ssoPending struct {
	access, refresh string
	user            userDTO
	exp             time.Time
}

var (
	ssoMu    sync.Mutex
	ssoCodes = map[string]ssoPending{}
)

func putSSOCode(access, refresh string, u userDTO) string {
	code := randToken()
	now := time.Now()
	ssoMu.Lock()
	// Sweep abandoned codes (issued but never exchanged) so the map can't grow
	// unbounded — takeSSOCode only deletes codes that are actually redeemed.
	for c, p := range ssoCodes {
		if now.After(p.exp) {
			delete(ssoCodes, c)
		}
	}
	ssoCodes[code] = ssoPending{access, refresh, u, now.Add(60 * time.Second)}
	ssoMu.Unlock()
	return code
}

func takeSSOCode(code string) (ssoPending, bool) {
	ssoMu.Lock()
	defer ssoMu.Unlock()
	p, ok := ssoCodes[code]
	if ok {
		delete(ssoCodes, code)
	}
	if !ok || time.Now().After(p.exp) {
		return ssoPending{}, false
	}
	return p, true
}

func oidcCookie(w http.ResponseWriter, name, val string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: val, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: maxAge,
	})
}

func cookieVal(r *http.Request, name string) string {
	if c, err := r.Cookie(name); err == nil {
		return c.Value
	}
	return ""
}

// GET /api/auth/oidc/login
func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if s.OIDC == nil || !s.OIDC.Enabled() {
		http.Error(w, "sso disabled", http.StatusNotFound)
		return
	}
	state, nonce, verifier := randToken(), randToken(), oauth2.GenerateVerifier()
	oidcCookie(w, "ah_oidc_state", state, 300)
	oidcCookie(w, "ah_oidc_nonce", nonce, 300)
	oidcCookie(w, "ah_oidc_pkce", verifier, 300)
	http.Redirect(w, r, s.OIDC.AuthCodeURL(state, nonce, verifier), http.StatusFound)
}

// GET /api/auth/oidc/callback?code=&state=
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if s.OIDC == nil || !s.OIDC.Enabled() {
		http.Error(w, "sso disabled", http.StatusNotFound)
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		// Log the IdP-provided error server-side; never reflect it to the client
		// (it is attacker-influenceable text).
		log.Printf("oidc callback: idp returned error %q", e)
		http.Error(w, "sso: authorization failed", http.StatusBadRequest)
		return
	}
	// Constant-time compare of the CSRF state token (cookie vs callback param).
	if st := cookieVal(r, "ah_oidc_state"); st == "" ||
		subtle.ConstantTimeCompare([]byte(st), []byte(q.Get("state"))) != 1 {
		http.Error(w, "sso: bad state", http.StatusBadRequest)
		return
	}
	claims, err := s.OIDC.Exchange(r.Context(), q.Get("code"), cookieVal(r, "ah_oidc_nonce"), cookieVal(r, "ah_oidc_pkce"))
	if err != nil {
		metrics.Logins.WithLabelValues("oidc", "fail").Inc()
		http.Error(w, "sso exchange failed", http.StatusUnauthorized)
		return
	}
	u, err := s.ensureSSOUser(claims, "oidc")
	if err != nil || !u.Enabled {
		http.Error(w, "sso user error", http.StatusUnauthorized)
		return
	}
	access, refresh, err := s.Auth.IssueTokens(u.ID, u.UPN, u.Role, u.TokenVersion)
	if err != nil {
		http.Error(w, "token error", http.StatusInternalServerError)
		return
	}
	metrics.Logins.WithLabelValues("oidc", "success").Inc()
	s.audit(r, s.DefaultOrgID, AuditSSOLogin, "user", u.UPN, "oidc")
	for _, n := range []string{"ah_oidc_state", "ah_oidc_nonce", "ah_oidc_pkce"} {
		oidcCookie(w, n, "", -1)
	}
	code := putSSOCode(access, refresh, toDTO(u))
	http.Redirect(w, r, "/admin/sso?code="+code, http.StatusFound)
}

// POST /api/auth/oidc/exchange {code} — SPA swaps the one-time code for tokens.
func (s *Server) handleOIDCExchange(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	p, ok := takeSSOCode(req.Code)
	if !ok {
		http.Error(w, "invalid or expired code", http.StatusUnauthorized)
		return
	}
	writeJSON(w, tokenResp{p.access, p.refresh, p.user})
}

func (s *Server) ensureSSOUser(c *sso.Claims, provider string) (*store.User, error) {
	if u, err := s.Store.GetUserBySSO(provider, c.Subject); err == nil {
		return u, nil
	}
	role := s.OIDCDefaultRole
	if role == "" {
		role = "user"
	}
	id, err := s.Store.CreateSSOUser(c.Username, c.Email, provider, c.Subject, role)
	if err != nil {
		return nil, err
	}
	_ = s.Store.AddMembership(s.DefaultOrgID, id, role) // JIT SSO users join the default org
	return s.Store.GetUserByID(id)
}
