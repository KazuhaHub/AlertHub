// Package twofa implements TOTP enrollment/verification + one-time recovery codes
// for admin accounts (Passwall pattern). The TOTP secret is stored AES-256-GCM
// encrypted (secretbox); recovery codes are stored as SHA-256 hashes.
package twofa

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/pquerna/otp/totp"

	"github.com/KazuhaHub/AlertHub/server/internal/secretbox"
	"github.com/KazuhaHub/AlertHub/server/internal/store"
)

type Service struct {
	store  *store.Store
	kek    []byte
	issuer string
}

func New(st *store.Store, kek []byte, issuer string) *Service {
	return &Service{store: st, kek: kek, issuer: issuer}
}

var ErrBadCode = errors.New("invalid code")

func (s *Service) Status(userID int64) (bool, error) {
	t, err := s.store.GetTOTP(userID)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return t.Enabled, nil
}

// Begin generates a new (not-yet-enabled) secret and returns the otpauth URL +
// base32 secret for QR / manual entry.
func (s *Service) Begin(userID int64, account string) (otpauthURL, secret string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: s.issuer, AccountName: account, SecretSize: 20})
	if err != nil {
		return "", "", err
	}
	enc, err := secretbox.Seal(s.kek, []byte(key.Secret()))
	if err != nil {
		return "", "", err
	}
	if err := s.store.UpsertTOTPPending(userID, enc); err != nil {
		return "", "", err
	}
	return key.URL(), key.Secret(), nil
}

// Enable validates the first code against the pending secret, enables TOTP, and
// returns freshly-generated one-time recovery codes (shown once).
func (s *Service) Enable(userID int64, code string) ([]string, error) {
	secret, err := s.secret(userID)
	if err != nil {
		return nil, err
	}
	if !totp.Validate(code, secret) {
		return nil, ErrBadCode
	}
	codes, hashes := genRecovery(10)
	if err := s.store.EnableTOTP(userID, strings.Join(hashes, "\n")); err != nil {
		return nil, err
	}
	return codes, nil
}

// VerifyLogin accepts a current TOTP code OR consumes a one-time recovery code.
func (s *Service) VerifyLogin(userID int64, code string) bool {
	t, err := s.store.GetTOTP(userID)
	if err != nil || !t.Enabled {
		return false
	}
	secret, err := s.decrypt(t.SecretEnc)
	if err == nil && totp.Validate(code, secret) {
		return true
	}
	// recovery code (one-time)
	want := hashCode(code)
	hashes := splitNonEmpty(t.Recovery)
	for i, h := range hashes {
		if h == want {
			remaining := append(append([]string{}, hashes[:i]...), hashes[i+1:]...)
			_ = s.store.SetTOTPRecovery(userID, strings.Join(remaining, "\n"))
			return true
		}
	}
	return false
}

// Disable requires a valid code (step-up), then removes TOTP.
func (s *Service) Disable(userID int64, code string) error {
	if !s.VerifyLogin(userID, code) {
		return ErrBadCode
	}
	return s.store.DeleteTOTP(userID)
}

func (s *Service) secret(userID int64) (string, error) {
	t, err := s.store.GetTOTP(userID)
	if err != nil {
		return "", err
	}
	return s.decrypt(t.SecretEnc)
}

func (s *Service) decrypt(enc []byte) (string, error) {
	pt, err := secretbox.Open(s.kek, enc)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func genRecovery(n int) (codes, hashes []string) {
	for i := 0; i < n; i++ {
		b := make([]byte, 6)
		_, _ = rand.Read(b)
		c := base64.RawURLEncoding.EncodeToString(b) // ~8 chars
		codes = append(codes, c)
		hashes = append(hashes, hashCode(c))
	}
	return codes, hashes
}

func hashCode(c string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(c)))
	return hex.EncodeToString(sum[:])
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, p := range strings.Split(s, "\n") {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
