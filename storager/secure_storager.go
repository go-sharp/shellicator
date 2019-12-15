// Package storager contains additional credential stores
// that implements the Storager interface for the shellicator lib.
package storager

import (
	"encoding/base64"
	"encoding/json"

	"github.com/go-sharp/shellicator/errors"
	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
)

// NewSecureStore creates a new secure storager.
func NewSecureStore(serviceName string) SecureStore {
	return SecureStore{serviceName: serviceName}
}

// SecureStore stores and retrieves tokens in a platform dependent secure storage.
type SecureStore struct {
	serviceName string
}

// RetrieveToken retrieves a token from the secure store.
func (s SecureStore) RetrieveToken(key string) (*oauth2.Token, error) {
	raw, err := keyring.Get(s.serviceName, key)
	if err != nil {
		if err == keyring.ErrNotFound {
			return nil, errors.ErrTokenNotFound
		}
		return nil, errors.ErrGeneric.WithWrappedError(err)
	}

	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, errors.ErrGeneric.WithWrappedError(err)
	}

	var token oauth2.Token
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, errors.ErrGeneric.WithWrappedError(err)
	}
	return &token, nil
}

// StoreToken stores a token in the secure store.
func (s SecureStore) StoreToken(key string, token *oauth2.Token) error {
	data, err := json.Marshal(token)
	if err != nil {
		return errors.ErrGeneric.WithMessageAndError("secureStore set token failed", err)
	}

	if err := keyring.Set(s.serviceName, key, base64.StdEncoding.EncodeToString(data)); err != nil {
		return errors.ErrGeneric.WithMessageAndError("secureStore set token failed", err)
	}

	return nil
}
