package jwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// package global variables
var secret string

// Init Initialize JWT
// JWT should be initialized in main,  before any JWT operation or behaviour will be undefined
func Init(s string) {
	secret = s
}

// Generate JWT Token for claim
func Generate(c IClaim, d time.Duration) (string, error) {
	claim := &CustomClaim{
		Id:   c.GetID(),
		Name: c.GetName(),
		Type: c.GetType(),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAtFunc(d)),
		},
	}
	return generate(claim)
}

// Parse JWT Token with CustomClaim
func Parse(tokenString string) (*CustomClaim, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaim{}, secretKeyFunc)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*CustomClaim)
	if !ok {
		return nil, errors.New("jwt token Claim is not CustomClaim")
	}

	return claims, nil
}

func generate(c jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	return token.SignedString([]byte(secret))
}

func secretKeyFunc(token *jwt.Token) (interface{}, error) {
	return []byte(secret), nil
}
