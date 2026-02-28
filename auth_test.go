package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ---------- Test SignAccessToken ----------
func TestSignAccessToken(t *testing.T) {
	config := &Config{
		AuthSecret:    []byte("secret"),
		RefreshSecret: []byte("secret1"),

		Method:    jwt.SigningMethodHS256,
		AccessTTL: 1 * time.Hour,
	}
	auth, _ := NewAuthService(config)

	claims := &JwtClaims{UserID: "123"}
	token, err := auth.SignAccessToken(claims)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if token == "" {
		t.Fatalf("expected non-empty token")
	}
}

// ---------- Test ValidateAccessToken ----------
func TestValidateAccessToken(t *testing.T) {
	config := &Config{
		AuthSecret:    []byte("secret"),
		RefreshSecret: []byte("secret1"),
		Method:        jwt.SigningMethodHS256,
		AccessTTL:     1 * time.Hour,
	}
	auth, _ := NewAuthService(config)

	claims := &JwtClaims{UserID: "123"}
	token, _ := auth.SignAccessToken(claims)

	got, err := auth.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got.UserID != "123" {
		t.Errorf("expected UserID 123, got %s", got.UserID)
	}
}

// ---------- Test SignedRefreshToken ----------
func TestSignedRefreshToken(t *testing.T) {
	config := &Config{
		RefreshSecret: []byte("refreshsecret"),
		Method:        jwt.SigningMethodHS256,
		RefreshTTL:    24 * time.Hour,
	}
	auth, _ := NewAuthService(config)

	claims := &JwtClaims{UserID: "456"}
	token, err := auth.SignedRefreshToken(claims)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if token == "" {
		t.Fatalf("expected non-empty token")
	}
}

// ---------- Test ValidateRefreshToken ----------
func TestValidateRefreshToken(t *testing.T) {
	config := &Config{
		RefreshSecret: []byte("refreshsecret"),
		Method:        jwt.SigningMethodHS256,
		RefreshTTL:    24 * time.Hour,
	}
	auth, _ := NewAuthService(config)

	claims := &JwtClaims{UserID: "456"}
	token, _ := auth.SignedRefreshToken(claims)

	got, err := auth.ValidateRefreshToken(token)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got.UserID != "456" {
		t.Errorf("expected UserID 456, got %s", got.UserID)
	}
}
