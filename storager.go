package shellicator

import (
	"fmt"

	"golang.org/x/oauth2"
)

type MemoryStorage map[string]*oauth2.Token

func (m MemoryStorage) RetrieveToken(key string) (*oauth2.Token, error) {
	if val, ok := m[key]; ok {
		return val, nil
	}

	return nil, fmt.Errorf("MemoryStorager: can't find token for key '%v'", key)
}

func (m MemoryStorage) StoreToken(key string, token *oauth2.Token) {
	m[key] = token
}
