package api

import (
	"net/http"

	"github.com/KazuhaHub/AlertHub/server/internal/metrics"
)

// GET /api/auth/saml/login — redirect to the IdP SSO (HTTP-Redirect binding).
func (s *Server) handleSAMLLogin(w http.ResponseWriter, r *http.Request) {
	if s.SAML == nil || !s.SAML.Enabled() {
		http.Error(w, "saml disabled", http.StatusNotFound)
		return
	}
	url, err := s.SAML.RedirectURL("/")
	if err != nil {
		http.Error(w, "saml login failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, url, http.StatusFound)
}

// POST /api/auth/saml/acs — Assertion Consumer Service (IdP posts SAMLResponse).
func (s *Server) handleSAMLACS(w http.ResponseWriter, r *http.Request) {
	if s.SAML == nil || !s.SAML.Enabled() {
		http.Error(w, "saml disabled", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	claims, err := s.SAML.ParseResponse(r)
	if err != nil {
		metrics.Logins.WithLabelValues("saml", "fail").Inc()
		http.Error(w, "saml: invalid response", http.StatusUnauthorized)
		return
	}
	u, err := s.ensureSSOUser(claims, "saml")
	if err != nil || !u.Enabled {
		http.Error(w, "saml user error", http.StatusUnauthorized)
		return
	}
	access, refresh, err := s.Auth.IssueTokens(u.ID, u.UPN, u.Role, u.TokenVersion)
	if err != nil {
		http.Error(w, "token error", http.StatusInternalServerError)
		return
	}
	metrics.Logins.WithLabelValues("saml", "success").Inc()
	s.audit(r, s.DefaultOrgID, AuditSSOLogin, "user", u.UPN, "saml")
	code := putSSOCode(access, refresh, toDTO(u))
	http.Redirect(w, r, "/admin/sso?code="+code, http.StatusFound)
}

// GET /api/auth/saml/metadata — SP metadata XML to register with the IdP.
func (s *Server) handleSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	if s.SAML == nil || !s.SAML.Enabled() {
		http.Error(w, "saml disabled", http.StatusNotFound)
		return
	}
	xmlBytes, err := s.SAML.MetadataXML()
	if err != nil {
		http.Error(w, "metadata error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write(xmlBytes)
}
