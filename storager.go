package shellicator

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	serr "github.com/go-sharp/shellicator/errors"
	"golang.org/x/oauth2"
)

// MemoryStorage implements an in-memory Storager.
type MemoryStorage map[string]*oauth2.Token

// RetrieveToken retrieves a token from the in-memory store.
func (m MemoryStorage) RetrieveToken(key string) (*oauth2.Token, error) {
	if val, ok := m[key]; ok {
		return val, nil
	}

	return nil, serr.ErrTokenNotFound.WithMessage(fmt.Sprintf("MemoryStorager can't find token for key '%v'", key))
}

// StoreToken stores a token in the in-memory store.
func (m MemoryStorage) StoreToken(key string, token *oauth2.Token) error {
	m[key] = token
	return nil
}

// FileStorage saves and retrieves token from the file system.
type FileStorage struct {
	Path string
	Name string
}

// RetrieveToken retrieves a token from the file store.
func (f FileStorage) RetrieveToken(key string) (*oauth2.Token, error) {
	store, err := f.loadMap()
	if err != nil {
		return nil, err
	}

	t, err := store.getToken(key)
	if err != nil {
		return nil, err
	}

	if t.RefreshToken == "" && time.Now().After(t.Expiry) {
		return nil, serr.ErrTokenNotFound.WithMessage(fmt.Sprintf("FileStorage can't find token for key '%v'", key))
	}
	return t, nil
}

// StoreToken stores a token in the file store.
func (f FileStorage) StoreToken(key string, token *oauth2.Token) error {
	store, err := f.loadMap()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	if err := store.setToken(key, token); err != nil {
		return err
	}

	return f.saveMap(store)
}

func (f FileStorage) saveMap(s fileStore) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return serr.ErrGeneric.WithMessageAndError("FileStorage failed to save tokens", err)
	}

	if err := ioutil.WriteFile(f.getFilePath(), raw, 0600); err != nil {
		return serr.ErrGeneric.WithMessageAndError("FileStorage failed to save tokens", err)
	}
	return nil
}

func (f FileStorage) loadMap() (fileStore, error) {
	data, err := ioutil.ReadFile(f.getFilePath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fileStore{}, nil
		}
		return nil, serr.ErrGeneric.WithMessageAndError("FileStorage failed to load file", err)
	}

	var store fileStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}
	return store, nil
}

func (f FileStorage) getFilePath() string {
	path, name := f.Path, f.Name
	if path == "" {
		path, _ = os.UserHomeDir()
	}

	if name == "" {
		name = ".shellicator-" + filepath.Base(os.Args[0])
	}

	return filepath.Clean(path + string(os.PathSeparator) + name)
}

type fileStore map[string]string

func (f fileStore) getToken(key string) (*oauth2.Token, error) {
	if v, ok := f[key]; ok {
		raw, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, serr.ErrGeneric.WithMessageAndError("fileStore get token failed", err)
		}
		var token oauth2.Token
		if err := json.Unmarshal(raw, &token); err != nil {
			return nil, serr.ErrGeneric.WithMessageAndError("fileStore get token failed", err)
		}
		return &token, nil
	}

	return nil, serr.ErrTokenNotFound.WithMessage(fmt.Sprintf("fileStore can't find token for key '%v'", key))
}

func (f *fileStore) setToken(key string, tok *oauth2.Token) error {
	raw, err := json.Marshal(tok)
	if err != nil {
		return serr.ErrGeneric.WithMessageAndError("fileStore set token failed", err)
	}

	(*f)[key] = base64.StdEncoding.EncodeToString(raw)
	return nil
}
