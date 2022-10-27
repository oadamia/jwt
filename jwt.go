package jwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// package global variables
var secret string
var expiresAtFunc = expiresAt

// Init Initialize JWT
// JWT should be initialized in main,  before any JWT operation or behaviour will be undefined
func Init(s string) {
	secret = s
}

// Generate JWT Token for user
func generate(c jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	return token.SignedString([]byte(secret))
}

func secretKeyFunc(token *jwt.Token) (interface{}, error) {
	return []byte(secret), nil
}

// SetExpiresAtFunc set expiresAtFunc
func SetExpiresAtFunc(expFunc func(d time.Duration) time.Time) error {
	if expFunc == nil {
		return errors.New("can not set nil as expires at function")
	}
	expiresAtFunc = expFunc
	return nil
}

func expiresAt(d time.Duration) time.Time {
	return time.Now().Add(d)
}
