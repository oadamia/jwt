package jwt

import (
	"errors"
	"time"
)

var expiresAtFunc = func(d time.Duration) time.Time { return time.Now().Add(d) }

// SetExpiresAtFunc set expiresAtFunc
func SetExpiresAtFunc(fn func(d time.Duration) time.Time) error {
	if fn == nil {
		return errors.New("can not set nil as expiresAtFunc")
	}
	expiresAtFunc = fn
	return nil
}
