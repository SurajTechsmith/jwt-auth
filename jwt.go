package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Config struct {
	AuthSecret    []byte
	RefreshSecret []byte
	Method        jwt.SigningMethod
	RefreshTTL    time.Duration
	AccessTTL     time.Duration
}

type JwtClaims struct {
	UserID string         `json:"user_id"`
	Data   map[string]any `json:"data,omitempty"`
	Type   string         `json:"type"`
	jwt.RegisteredClaims
}

type AuthService struct {
	config *Config
}

func NewAuthService(config *Config) (*AuthService, error) {

	if config == nil {
		return nil, ErrConfigNotReady
	}

	if config.Method == nil {
		config.Method = jwt.SigningMethodHS256
	}

	return &AuthService{config: config}, nil
}

func (a *AuthService) SignAccessToken(claims *JwtClaims) (string, error) {
	if claims.UserID == "" {
		return "", ErrMissingUserID
	}

	ttl := a.config.AccessTTL
	if ttl == 0 {
		ttl = 15 * time.Minute
	}
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(ttl))
	claims.IssuedAt = jwt.NewNumericDate(time.Now())

	claims.Type = "access"

	token := jwt.NewWithClaims(a.config.Method, claims)

	signedToken, err := token.SignedString(a.config.AuthSecret)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func (a *AuthService) ValidateAccessToken(tokenstring string) (*JwtClaims, error) {
	if a == nil || a.config == nil {
		return nil, ErrServiceNotReady
	}
	claims := &JwtClaims{}
	token, err := jwt.ParseWithClaims(tokenstring, claims, func(t *jwt.Token) (any, error) {

		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}

		return a.config.AuthSecret, nil
	}, jwt.WithLeeway(5*time.Second))

	if err != nil {
		return nil, err
	}

	if claims.Type != "access" {
		return nil, ErrInvalidTokenType
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil

}

func (a *AuthService) SignRefreshToken(claims *JwtClaims) (string, error) {
	if a == nil || a.config == nil {
		return "", ErrServiceNotReady
	}
	claims.Type = "refresh"

	ttl := a.config.RefreshTTL
	if ttl == 0 {
		ttl = 7 * 24 * time.Hour
	}
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(ttl))
	claims.IssuedAt = jwt.NewNumericDate(time.Now())

	refreshToken := jwt.NewWithClaims(a.config.Method, claims)

	signedToken, err := refreshToken.SignedString(a.config.RefreshSecret)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func (a *AuthService) ValidateRefreshToken(tokenstring string) (*JwtClaims, error) {
	if a == nil || a.config == nil {
		return nil, ErrServiceNotReady
	}
	claims := &JwtClaims{}

	token, err := jwt.ParseWithClaims(tokenstring, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return a.config.RefreshSecret, nil
	}, jwt.WithLeeway(5*time.Second))

	if err != nil {
		return nil, err
	}

	if claims.Type != "refresh" {
		return nil, ErrInvalidTokenType
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}
