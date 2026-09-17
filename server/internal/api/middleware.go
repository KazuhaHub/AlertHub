package api

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/KazuhaHub/AlertHub/server/internal/auth"
	"github.com/KazuhaHub/AlertHub/server/internal/store"
)

type ctxKey int

const claimsCtxKey ctxKey = 1

func bearer(h string) string {
	const p = "Bearer "
	if strings.HasPrefix(h, p) {
		return strings.TrimSpace(h[len(p):])
	}
	return ""
}

var roleRank = map[string]int{"user": 0, "operator": 1, "admin": 2}

// authn validates a request. Returns adminTok=true for the static admin token
// (scripts/automation → treated as super); otherwise a valid access JWT for an
// enabled, non-token-revoked user. On failure it writes 401 and returns ok=false.
func (s *Server) authn(w http.ResponseWriter, r *http.Request) (claims *auth.Claims, u *store.User, adminTok, ok bool) {
	raw := bearer(r.Header.Get("Authorization"))
	if raw == "" {
		if c, err := r.Cookie("ah_access"); err == nil {
			raw = c.Value
		}
	}
	if raw == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, nil, false, false
	}
	if s.AdminToken != "" && subtle.ConstantTimeCompare([]byte(raw), []byte(s.AdminToken)) == 1 {
		return nil, nil, true, true
	}
	c, err := s.Auth.Verify(raw, auth.SubjectAccess)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, nil, false, false
	}
	user, err := s.Store.GetUserByID(c.UserID)
	if err != nil || !user.Enabled || user.TokenVersion != c.TokenVersion {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, nil, false, false
	}
	return c, user, false, true
}

// requireRole gates by coarse role rank (legacy/self-service endpoints).
func (s *Server) requireRole(min string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, u, adminTok, ok := s.authn(w, r)
		if !ok {
			return
		}
		if adminTok {
			next(w, r)
			return
		}
		if roleRank[u.Role] < roleRank[min] {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), claimsCtxKey, claims)))
	}
}

// requirePerm gates by a fine-grained permission, resolved from the user's
// membership role in the active org (RBAC). Admin token and super-admins bypass.
func (s *Server) requirePerm(perm string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, u, adminTok, ok := s.authn(w, r)
		if !ok {
			return
		}
		if adminTok || u.IsSuperadmin {
			next(w, r)
			return
		}
		// Must be a member of the active org (tenant isolation), and the
		// membership role must grant the permission.
		role, ok := s.Store.GetMembershipRole(s.orgFor(r), u.ID)
		if !ok || !auth.RoleHasPerm(role, perm) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), claimsCtxKey, claims)))
	}
}

func claimsFrom(r *http.Request) *auth.Claims {
	c, _ := r.Context().Value(claimsCtxKey).(*auth.Claims)
	return c
}
