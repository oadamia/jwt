package jwt

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type IClaim interface {
	GetID() int
	GetName() string
	GetType() string
}

// CustomClaim jwt claim
type CustomClaim struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
	jwt.RegisteredClaims
}

// Generate JWT Token for user
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

// Parse JWT Token with UserClaim
func ParseJWT(tokenString string) (*CustomClaim, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaim{}, secretKeyFunc)
	if err != nil {
		return nil, err
	}

	claims, _ := token.Claims.(*CustomClaim)
	return claims, nil
}
