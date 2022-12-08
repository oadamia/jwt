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
	SetExpiresAtFunc(mock.ExpiresAt)

	os.Exit(m.Run())
}

func TestGenerate(t *testing.T) {
	duration := 30 * time.Second

	claim := mock.Claim{
		ID:   1,
		Name: "test",
		Type: "user",
	}

	t.Run("Generate", func(t *testing.T) {
		assert := assert.New(t)
		str, err := Generate(claim, duration)

		assert.Equal("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwibmFtZSI6InRlc3QiLCJ0eXBlIjoidXNlciIsImV4cCI6LTYyMTM1NTk2ODAwfQ.LMwuglUNvAhU6-ZXeqaewn90Uw0h2uOz-xqKJWaKVOA", str)
		assert.NoError(err)
	})
}

func TestUserJWT(t *testing.T) {
	generatorTime, _ := time.Parse(time.RFC3339, "2020-00-00T00:00:00Z")

	t.Run("Parse jwt", func(t *testing.T) {
		jwt.TimeFunc = func() time.Time {
			return generatorTime
		}

		assert := assert.New(t)
		claim, err := Parse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJ1c2VyX25hbWUiOiJ0ZXN0X3VzZXIiLCJ1c2VyX3R5cGUiOiJhZG1pbiIsImV4cCI6MTAwfQ.wfD_SDjGjKbmvL7xHjKFsaTSZfg0Afl1ENSJC-nJAVk")

		assert.Equal("&{UserID:1 UserName:test_user UserType:admin StandardClaims:{Audience: ExpiresAt:100 Id: IssuedAt:0 Issuer: NotBefore:0 Subject:}}", fmt.Sprintf("%+v", claim))
		assert.NoError(err)

		jwt.TimeFunc = time.Now

	})

	t.Run("Parse User jwt with expired token", func(t *testing.T) {
		assert := assert.New(t)
		claim, err := Parse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJ1c2VyX25hbWUiOiJ0ZXN0X3VzZXIiLCJ1c2VyX3R5cGUiOiJhZG1pbiIsImV4cCI6MTAwfQ.wfD_SDjGjKbmvL7xHjKFsaTSZfg0Afl1ENSJC-nJAVk")

		assert.Equal("<nil>", fmt.Sprintf("%+v", claim))
		assert.Error(err)
	})

	t.Run("Parse User jwt with invalid token", func(t *testing.T) {
		assert := assert.New(t)
		claim, err := Parse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJ1c2VyX25hbWUiOiJ0ZXN0X3VzZXIiLCJ1c2VyX3R5cGUiOiJhZG1pbiIsImV4cCI6MTAwfQ.wfD_SDjGjKbmvL7xHjKFsaTSZfg0Afl1ENSJC-nJAVk")

		assert.Equal("<nil>", fmt.Sprintf("%+v", claim))
		assert.Error(err)
	})

	t.Run("Parse User jwt with invalid claim", func(t *testing.T) {
		jwt.TimeFunc = func() time.Time {
			return generatorTime
		}

		assert := assert.New(t)
		claim, err := Parse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzZXNzaW9uX2lkIjoiMTFfMTAwNV8yMjY4ZTEzOS05MTQ3LTQwZDAtOWE1MS03ZTMwYjEwYTU2NDYiLCJnYW1lX2lkIjoib3JiaXRhbC5rZW5vIiwicGxheWVyX2lkIjoiOTIwIiwiZXhwIjoxNzA3NjYzOTkwfQ.DenmAu3E9rq7DBRhOP5AEn8L5ta7m8GJxSRG3sAxPJY")

		assert.Equal("&{UserID:0 UserName: UserType: StandardClaims:{Audience: ExpiresAt:1707663990 Id: IssuedAt:0 Issuer: NotBefore:0 Subject:}}", fmt.Sprintf("%+v", claim))
		assert.Nil(err)

		jwt.TimeFunc = time.Now
	})

	t.Run("ExpiresAt Function", func(t *testing.T) {
		assert := assert.New(t)
		expiresAtDate := expiresAtFunc
		testDate := time.Now().Add(time.Hour * 120).Unix()

		assert.Equal(expiresAtDate, testDate)

	})

}
