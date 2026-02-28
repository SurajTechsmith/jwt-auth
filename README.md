# Go JWT Auth Library

A lightweight Go library for JWT-based authentication with support for **access tokens**, **refresh tokens**, and helper functions for context and headers.

---

## Features

- Sign and validate **access tokens**  
- Sign and validate **refresh tokens**  
- Custom claims support (`JwtClaims`)  
- Helper functions:
  - Extract token from HTTP `Authorization` header
  - Inject claims into `context.Context`  
- Configurable token TTL and signing method  
- Easy to integrate into any Go project

---

## Installation

```bash
go get github.com/yourusername/go-auth

```

---

## Usage

### 1. Configure AuthService

```go
package main

import (
	"fmt"
	"time"

	"github.com/yourusername/go-auth"
	"github.com/golang-jwt/jwt/v5"
)

func main() {
	config := &auth.Config{
		AuthSecret:    []byte("your-access-secret"),
		RefreshSecret: []byte("your-refresh-secret"),
		Method:        jwt.SigningMethodHS256,
		AccessTTL:     15 * time.Minute,
		RefreshTTL:    7 * 24 * time.Hour,
	}

	authService, err := auth.NewAuthService(config)
	if err != nil {
		panic(err)
	}
}
```

---

### 2. Signing Tokens

```go
claims := &auth.JwtClaims{
	UserID: "123",
	Data: map[string]string{
		"role": "admin",
	},
}

// Sign access token
accessToken, err := authService.SignAccessToken(claims)

// Sign refresh token
refreshToken, err := authService.SignedRefreshToken(claims)
```


Data is for any custom claims you might like to add but UserID is must
---

### 3. Validating Tokens

```go
// Validate access token
validatedClaims, err := authService.ValidateAccessToken(accessToken)

// Validate refresh token
refreshClaims, err := authService.ValidateRefreshToken(refreshToken)
```

---

### 4. Helper Functions

#### Extract token from HTTP header

```go
header := r.Header.Get("Authorization")
token, err := auth.ExtractTokenHeader(header)
```

#### Inject claims into context

```go
ctx := auth.InjectContext(r.Context(), validatedClaims)
next.ServeHTTP(w, r.WithContext(ctx))


```

---

## Configuration Options

| Field         | Description                         |
| ------------- | ----------------------------------- |
| AuthSecret    | Secret for signing access tokens    |
| RefreshSecret | Secret for signing refresh tokens   |
| Method        | JWT signing method (default: HS256) |
| AccessTTL     | Access token time-to-live           |
| RefreshTTL    | Refresh token time-to-live          |


---

## Errors

| Error                 | Description                                |
| --------------------- | ------------------------------------------ |
| `ErrInvalidToken`     | Token is malformed or signature is invalid |
| `ErrInvalidTokenType` | Token type mismatch (access vs refresh)    |
| `ErrServiceNotReady`  | Auth service was not initialized           |
| `ErrMissingUserID`    | UserID is missing from claims              |


use errors.Is to determine specific error
if errors.Is(err, ErrNotFound) {
		fmt.Println("Found the expected error using errors.Is")
        or anything you like to do
	}
---

## Tests

Run unit tests:

```bash
go test -v
```

* Table-driven tests for all functions
* Covers happy paths and common edge cases

