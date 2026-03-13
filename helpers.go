package auth

import (
	"context"
	"strings"
)

type claimCtxKey string

func ExtractTokenHeader(header string) (string, error) {

	if header == "" {
		return "", ErrInvalidToken
	}

	str := strings.Split(header, " ")
	if len(str) != 2 || str[0] != "Bearer" {
		return "", ErrInvalidToken
	}

	return str[1], nil
}

func InjectContext(ctx context.Context, claims JwtClaims, claimsKey claimCtxKey) context.Context {
	ctx = context.WithValue(ctx, claimsKey, claims)

	return ctx
}
