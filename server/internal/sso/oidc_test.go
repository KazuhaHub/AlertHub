package sso_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/KazuhaHub/AlertHub/server/internal/sso"
)

// mockIDP is a minimal OIDC provider: discovery + JWKS + token endpoint returning
// a self-signed RS256 id_token. Lets us e2e-verify sso.Exchange with no real IdP.
func mockIDP(t *testing.T, clientID, nonce string) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                srv.URL,
			"authorization_endpoint":                srv.URL + "/authorize",
			"token_endpoint":                        srv.URL + "/token",
			"jwks_uri":                              srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		eBuf := make([]byte, 8)
		binary.BigEndian.PutUint64(eBuf, uint64(key.E))
		i := 0
		for i < len(eBuf)-1 && eBuf[i] == 0 {
			i++
		}
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(eBuf[i:]),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := jwt.MapClaims{
			"iss": srv.URL, "aud": clientID, "sub": "user-123",
			"email": "alice@example.com", "preferred_username": "alice", "name": "Alice",
			"nonce": nonce, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "test-key"
		idToken, err := tok.SignedString(key)
		if err != nil {
			t.Errorf("sign id_token: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": idToken,
		})
	})
	return srv, key
}

func TestOIDCExchange(t *testing.T) {
	const clientID, nonce = "alerthub", "nonce-xyz"
	idp, _ := mockIDP(t, clientID, nonce)
	defer idp.Close()

	ctx := context.Background()
	o, err := sso.NewOIDC(ctx, sso.OIDCConfig{
		Enabled: true, IssuerURL: idp.URL, ClientID: clientID, ClientSecret: "secret",
		RedirectURL: "http://localhost:8080/api/auth/oidc/callback",
	})
	if err != nil {
		t.Fatalf("NewOIDC: %v", err)
	}
	if !o.Enabled() {
		t.Fatal("should be enabled")
	}
	if url := o.AuthCodeURL("state1", nonce, "verifier1234567890verifier1234567890verifier"); url == "" {
		t.Fatal("empty auth url")
	}

	claims, err := o.Exchange(ctx, "any-code", nonce, "verifier1234567890verifier1234567890verifier")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if claims.Subject != "user-123" || claims.Email != "alice@example.com" || claims.Username != "alice" {
		t.Errorf("claims wrong: %+v", claims)
	}

	// wrong nonce must be rejected
	if _, err := o.Exchange(ctx, "any-code", "WRONG", "verifier1234567890verifier1234567890verifier"); err == nil {
		t.Fatal("nonce mismatch must error")
	}
}

func TestOIDCDisabled(t *testing.T) {
	o, err := sso.NewOIDC(context.Background(), sso.OIDCConfig{Enabled: false})
	if err != nil || o.Enabled() {
		t.Fatal("disabled OIDC should be inert with no error")
	}
}
