package jwt

import (
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
