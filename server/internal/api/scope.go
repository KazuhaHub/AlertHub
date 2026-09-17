package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"

	"github.com/KazuhaHub/AlertHub/server/internal/auth"
)

// apiKeyPrefix marks a service-account API key (vs a human JWT).
const apiKeyPrefix = "ahk_"

const orgCtxKey ctxKey = 2 // service-account org_id stashed by requireScope

// orgFor resolves the active org for a request: an X-Org-Id header (membership is
// enforced by requirePerm), else the API key's org, else the default org.
func (s *Server) orgFor(r *http.Request) int64 {
	if h := r.Header.Get("X-Org-Id"); h != "" {
		if id, err := strconv.ParseInt(h, 10, 64); err == nil && id > 0 {
			return id
		}
	}
	if v, ok := r.Context().Value(orgCtxKey).(int64); ok && v != 0 {
		return v
	}
	return s.DefaultOrgID
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func scopeAllowed(scopes, want string) bool {
	for _, sc := range strings.Split(scopes, ",") {
		sc = strings.TrimSpace(sc)
		if sc == want || sc == "*" {
			return true
		}
	}
	return false
}

// requireScope authenticates a machine caller via a service-account API key with
// the required scope; otherwise it falls back to admin (session JWT or admin
// token), so an operator can also use the endpoint.
func (s *Server) requireScope(scope string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := bearer(r.Header.Get("Authorization"))
		if strings.HasPrefix(raw, apiKeyPrefix) {
			sa, err := s.Store.GetServiceAccountByTokenHash(sha256hex(raw))
			if err == nil && !sa.Disabled && scopeAllowed(sa.Scopes, scope) {
				_ = s.Store.TouchServiceAccount(sa.ID)
				next(w, r.WithContext(context.WithValue(r.Context(), orgCtxKey, sa.OrgID)))
				return
			}
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		s.requireRole(auth.RoleAdmin, next)(w, r)
	}
}
