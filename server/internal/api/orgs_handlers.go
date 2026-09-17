package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/KazuhaHub/AlertHub/server/internal/store"
)

type orgDTO struct {
	ID   int64  `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// isSuper reports whether the request is the platform super-admin (static admin
// token, or a session user with is_superadmin).
func (s *Server) isSuper(r *http.Request) bool {
	c := claimsFrom(r)
	if c == nil {
		return true // admin-token path (authn already validated it)
	}
	u, err := s.Store.GetUserByID(c.UserID)
	return err == nil && u.IsSuperadmin
}

// /api/orgs — GET lists visible orgs (super → all, else member orgs); POST
// creates an org (super-admin only) with the creator as owner.
func (s *Server) handleOrgs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c := claimsFrom(r)
		var orgs []store.Org
		var err error
		if c != nil && !s.isSuper(r) {
			orgs, err = s.Store.OrgsForUser(c.UserID)
		} else {
			orgs, err = s.Store.ListOrgs()
		}
		if err != nil {
			http.Error(w, "list failed", http.StatusInternalServerError)
			return
		}
		out := make([]orgDTO, 0, len(orgs))
		for _, o := range orgs {
			out = append(out, orgDTO{ID: o.ID, Slug: o.Slug, Name: o.Name})
		}
		writeJSON(w, out)

	case http.MethodPost:
		if !s.isSuper(r) {
			http.Error(w, "super-admin only", http.StatusForbidden)
			return
		}
		var req struct {
			Slug string `json:"slug"`
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Slug) == "" {
			http.Error(w, "slug required", http.StatusBadRequest)
			return
		}
		if req.Name == "" {
			req.Name = req.Slug
		}
		id, err := s.Store.CreateOrg(req.Slug, req.Name)
		if err != nil {
			http.Error(w, "create failed (slug taken?)", http.StatusBadRequest)
			return
		}
		if c := claimsFrom(r); c != nil {
			_ = s.Store.AddMembership(id, c.UserID, "owner") // creator owns the new org
		}
		s.audit(r, id, AuditOrgCreate, "org", strconv.FormatInt(id, 10), req.Slug)
		writeJSON(w, orgDTO{ID: id, Slug: req.Slug, Name: req.Name})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
