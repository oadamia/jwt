package jwt

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/oadamia/jwt/mock"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	Init("jwt")

	os.Exit(m.Run())
}

func TestGenerate(t *testing.T) {
	duration := 30 * time.Second

	claim := mock.Claim{
		ID:   1,
		Name: "test",
		Type: "user",
	}

	t.Run("Generate Real", func(t *testing.T) {

		assert := assert.New(t)
		_, err := Generate(claim, duration)

		assert.NoError(err)
	})

	SetExpiresAtFunc(mock.ExpiresAt)

	t.Run("Generate", func(t *testing.T) {

		assert := assert.New(t)
		str, err := Generate(claim, duration)

		assert.Equal("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwibmFtZSI6InRlc3QiLCJ0eXBlIjoidXNlciIsImV4cCI6MTU3NzgzNjg2MH0._e6meYmJrnrUuA_yfO1yYrKWJR7Z0Yzw3C2jvOAtWRg", str)
		assert.NoError(err)
	})

}

func TestUserJWT(t *testing.T) {
	generatorTime, _ := time.Parse(time.RFC3339, "2020-01-01T00:00:01Z")

	t.Run("Parse jwt", func(t *testing.T) {
		jwt.TimeFunc = func() time.Time {
			return generatorTime
		}

		assert := assert.New(t)
		claim, err := Parse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwibmFtZSI6InRlc3QiLCJ0eXBlIjoidXNlciIsImV4cCI6MTU3NzgzNjg2MH0._e6meYmJrnrUuA_yfO1yYrKWJR7Z0Yzw3C2jvOAtWRg")

		assert.Equal("&{Id:1 Name:test Type:user RegisteredClaims:{Issuer: Subject: Audience:[] ExpiresAt:2020-01-01 04:01:00 +0400 +04 NotBefore:<nil> IssuedAt:<nil> ID:}}", fmt.Sprintf("%+v", claim))
		assert.NoError(err)

		jwt.TimeFunc = time.Now

	})

	t.Run("Parse User jwt with expired token", func(t *testing.T) {
		assert := assert.New(t)
		claim, err := Parse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwibmFtZSI6InRlc3QiLCJ0eXBlIjoidXNlciIsImV4cCI6MTU3NzgzNjg2MH0._e6meYmJrnrUuA_yfO1yYrKWJR7Z0Yzw3C2jvOAtWRg")

		assert.Equal("<nil>", fmt.Sprintf("%+v", claim))
		assert.Error(err)
	})

	t.Run("Parse User jwt with invalid token", func(t *testing.T) {
		assert := assert.New(t)
		claim, err := Parse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwibmFtZSI6InRlc3QiLCJ0eXBlIjoidXNlciIsImV4cCI6MTU3NzgzNjg2MH0._e6meYmJrnrUuA_yfO1yYrKWJR7Z0Yzw3C2jvOAtWR")

		assert.Equal("<nil>", fmt.Sprintf("%+v", claim))
		assert.Error(err)
	})

	t.Run("Parse User jwt with empty claim", func(t *testing.T) {
		jwt.TimeFunc = func() time.Time {
			return generatorTime
		}

		assert := assert.New(t)
		claim, err := Parse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MCwibmFtZSI6IiIsInR5cGUiOiIiLCJleHAiOjE1Nzc4MzY4NjB9.woDc9P3mvnZJ_EZmbQMoMxg2C-GqUoCq8A5vREtiLe4")

		assert.Equal("&{Id:0 Name: Type: RegisteredClaims:{Issuer: Subject: Audience:[] ExpiresAt:2020-01-01 04:01:00 +0400 +04 NotBefore:<nil> IssuedAt:<nil> ID:}}", fmt.Sprintf("%+v", claim))
		assert.Nil(err)

		jwt.TimeFunc = time.Now
	})

	t.Run("set nil as expiresAt funciton", func(t *testing.T) {
		assert := assert.New(t)
		err := SetExpiresAtFunc(nil)
		assert.Error(err)
	})

}
