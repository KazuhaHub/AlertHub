package twofa_test

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/KazuhaHub/AlertHub/server/internal/store"
	"github.com/KazuhaHub/AlertHub/server/internal/twofa"
)

func TestEnrollVerifyRecovery(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	uid, err := st.CreateUser(&store.User{UPN: "admin", Role: "admin", Enabled: true, PasswordHash: "x"})
	if err != nil {
		t.Fatal(err)
	}
	kek := make([]byte, 32) // zero key is fine for a unit test
	svc := twofa.New(st, kek, "Test")

	if on, _ := svc.Status(uid); on {
		t.Fatal("should start disabled")
	}
	url, secret, err := svc.Begin(uid, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(url, "otpauth://") {
		t.Fatalf("bad otpauth url: %q", url)
	}

	code, _ := totp.GenerateCode(secret, time.Now())
	recovery, err := svc.Enable(uid, code)
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if len(recovery) != 10 {
		t.Fatalf("want 10 recovery codes, got %d", len(recovery))
	}
	if on, _ := svc.Status(uid); !on {
		t.Fatal("should be enabled after Enable")
	}

	// wrong code on enable would have failed:
	if _, err := twofa.New(st, kek, "Test").Enable(uid, "000000"); err == nil {
		// already enabled; Enable re-validates pending secret — wrong code must fail
		t.Fatal("enable with wrong code should fail")
	}

	good, _ := totp.GenerateCode(secret, time.Now())
	if !svc.VerifyLogin(uid, good) {
		t.Fatal("valid TOTP code rejected")
	}
	if svc.VerifyLogin(uid, "000000") {
		t.Fatal("wrong code accepted")
	}

	// recovery code is one-time
	rc := recovery[0]
	if !svc.VerifyLogin(uid, rc) {
		t.Fatal("recovery code rejected")
	}
	if svc.VerifyLogin(uid, rc) {
		t.Fatal("recovery code reused (must be one-time)")
	}

	// disable requires a valid code
	if err := svc.Disable(uid, "000000"); err == nil {
		t.Fatal("disable with wrong code should fail")
	}
	cur, _ := totp.GenerateCode(secret, time.Now())
	if err := svc.Disable(uid, cur); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if on, _ := svc.Status(uid); on {
		t.Fatal("should be disabled after Disable")
	}
}
