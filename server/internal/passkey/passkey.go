// Package passkey implements WebAuthn/passkey registration + usernameless
// (discoverable) login, modeled on the Passwall panel. The Ed25519 alert-signing
// key is unrelated — this is human admin auth only. RP-ID/origin come from config
// (never the Host header) to avoid RP-ID poisoning.
package passkey

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/KazuhaHub/AlertHub/server/internal/store"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type Service struct {
	wa    *webauthn.WebAuthn
	store *store.Store

	mu       sync.Mutex
	sessions map[string]sessionEntry
}

type sessionEntry struct {
	data    webauthn.SessionData
	userID  int64 // registration: owning user; discoverable login: 0
	expires time.Time
}

func New(st *store.Store, rpID, rpOrigin, rpName string) (*Service, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: rpName,
		RPOrigins:     []string{rpOrigin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		},
	})
	if err != nil {
		return nil, err
	}
	return &Service{wa: wa, store: st, sessions: map[string]sessionEntry{}}, nil
}

// --- webauthn.User adapter (user handle = 8-byte big-endian user id) ---
type waUser struct {
	id    int64
	name  string
	creds []webauthn.Credential
}

func userHandle(id int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(id))
	return b
}

func (u *waUser) WebAuthnID() []byte                         { return userHandle(u.id) }
func (u *waUser) WebAuthnName() string                       { return u.name }
func (u *waUser) WebAuthnDisplayName() string                { return u.name }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (s *Service) loadUser(userID int64, upn string) (*waUser, error) {
	pks, err := s.store.ListPasskeys(userID)
	if err != nil {
		return nil, err
	}
	creds := make([]webauthn.Credential, 0, len(pks))
	for _, p := range pks {
		var c webauthn.Credential
		if json.Unmarshal(p.Credential, &c) == nil {
			creds = append(creds, c)
		}
	}
	return &waUser{id: userID, name: upn, creds: creds}, nil
}

// --- ephemeral begin/finish session store ---
func (s *Service) putSession(data webauthn.SessionData, userID int64) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	id := base64.RawURLEncoding.EncodeToString(b)
	now := time.Now()
	s.mu.Lock()
	// Sweep abandoned sessions (begin without a matching finish) so the map can't
	// grow unbounded — takeSession only removes sessions that are actually used.
	for k, e := range s.sessions {
		if now.After(e.expires) {
			delete(s.sessions, k)
		}
	}
	s.sessions[id] = sessionEntry{data: data, userID: userID, expires: now.Add(5 * time.Minute)}
	s.mu.Unlock()
	return id
}

func (s *Service) takeSession(id string) (sessionEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.sessions[id]
	if ok {
		delete(s.sessions, id)
	}
	if !ok || time.Now().After(e.expires) {
		return sessionEntry{}, false
	}
	return e, true
}

var ErrSession = errors.New("invalid or expired passkey session")

// --- registration ---
func (s *Service) BeginRegistration(userID int64, upn string) (*protocol.CredentialCreation, string, error) {
	u, err := s.loadUser(userID, upn)
	if err != nil {
		return nil, "", err
	}
	creation, session, err := s.wa.BeginRegistration(u)
	if err != nil {
		return nil, "", err
	}
	return creation, s.putSession(*session, userID), nil
}

func (s *Service) FinishRegistration(userID int64, upn, sessionID, name string, r *http.Request) error {
	e, ok := s.takeSession(sessionID)
	if !ok || e.userID != userID {
		return ErrSession
	}
	u, err := s.loadUser(userID, upn)
	if err != nil {
		return err
	}
	cred, err := s.wa.FinishRegistration(u, e.data, r)
	if err != nil {
		return err
	}
	blob, _ := json.Marshal(cred)
	if name == "" {
		name = "Passkey"
	}
	_, err = s.store.AddPasskey(&store.Passkey{
		UserID:       userID,
		CredentialID: base64.RawURLEncoding.EncodeToString(cred.ID),
		Credential:   blob,
		SignCount:    int64(cred.Authenticator.SignCount),
		Name:         name,
	})
	return err
}

// --- usernameless (discoverable) login ---
func (s *Service) BeginLogin() (*protocol.CredentialAssertion, string, error) {
	assertion, session, err := s.wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, "", err
	}
	return assertion, s.putSession(*session, 0), nil
}

// FinishLogin verifies the assertion and returns the resolved, enabled user.
func (s *Service) FinishLogin(sessionID string, r *http.Request) (*store.User, error) {
	e, ok := s.takeSession(sessionID)
	if !ok {
		return nil, ErrSession
	}
	var resolved *store.User
	handler := func(rawID, uh []byte) (webauthn.User, error) {
		if len(uh) != 8 {
			return nil, errors.New("bad user handle")
		}
		su, err := s.store.GetUserByID(int64(binary.BigEndian.Uint64(uh)))
		if err != nil {
			return nil, err
		}
		resolved = su
		return s.loadUser(su.ID, su.UPN)
	}
	cred, err := s.wa.FinishDiscoverableLogin(handler, e.data, r)
	if err != nil {
		return nil, err
	}
	if resolved == nil || !resolved.Enabled {
		return nil, errors.New("user not found or disabled")
	}
	_ = s.store.UpdatePasskeyUsage(base64.RawURLEncoding.EncodeToString(cred.ID), int64(cred.Authenticator.SignCount))
	return resolved, nil
}

func (s *Service) List(userID int64) ([]store.Passkey, error) { return s.store.ListPasskeys(userID) }
func (s *Service) Delete(userID, id int64) error              { return s.store.DeletePasskey(userID, id) }
