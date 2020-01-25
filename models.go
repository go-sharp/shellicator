package shellicator

import (
	"encoding/json"
	"math"
	"time"
)

const (
	devTokRespAuthorizationPending = "authorization_pending"
	devTokRespSlowDown             = "slow_down"
	devTokRespAccessDenied         = "access_denied"
	devTokRespExpiredToken         = "expired_token"
)

// provConfig holds the provider configuration.
type provConfig struct {
	provider       Provider
	useDeviceGrant bool
}

type devAccessTokenErrResponse struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// deviceGrantResponse is the oauth2 device grant response see https://tools.ietf.org/html/rfc8628#section-3.2
type deviceGrantResponse struct {
	DeviceCode              string `json:"device_code,omitempty"`
	UserCode                string `json:"user_code,omitempty"`
	VerificationURI         string `json:"verification_uri,omitempty"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	Expires                 int    `json:"expires_in,omitempty"` // expires in seconds
	Interval                int    `json:"interval,omitempty"`   // interval in seconds
}

func (d deviceGrantResponse) getInterval() time.Duration {
	// As specified in https://tools.ietf.org/html/rfc8628#section-3.2
	// at least wait for 5 seconds.
	if d.Interval < 5 {
		return time.Second * 5
	}
	return time.Second * time.Duration(d.Interval)
}

// This part below is copied from the go library https://golang.org/x/oauth2/internal/token.go

// tokenJSON is the struct representing the HTTP response from OAuth2
// providers returning a token in JSON form.
type tokenJSON struct {
	AccessToken  string         `json:"access_token"`
	TokenType    string         `json:"token_type"`
	RefreshToken string         `json:"refresh_token"`
	ExpiresIn    expirationTime `json:"expires_in"` // at least PayPal returns string, while most return number
}

func (e *tokenJSON) expiry() (t time.Time) {
	if v := e.ExpiresIn; v != 0 {
		return time.Now().Add(time.Duration(v) * time.Second)
	}
	return
}

type expirationTime int32

func (e *expirationTime) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	var n json.Number
	err := json.Unmarshal(b, &n)
	if err != nil {
		return err
	}
	i, err := n.Int64()
	if err != nil {
		return err
	}
	if i > math.MaxInt32 {
		i = math.MaxInt32
	}
	*e = expirationTime(i)
	return nil
}
