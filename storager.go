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

	"golang.org/x/oauth2"
)

type MemoryStorage map[string]*oauth2.Token

func (m MemoryStorage) RetrieveToken(key string) (*oauth2.Token, error) {
	if val, ok := m[key]; ok {
		return val, nil
	}

	return nil, sherr{Err: ErrTokenNotFound, message: fmt.Sprintf("MemoryStorager can't find token for key '%v'", key)}
}

func (m MemoryStorage) StoreToken(key string, token *oauth2.Token) error {
	m[key] = token
	return nil
}

type FileStorage struct {
	Path string
	Name string
}

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
		return nil, sherr{Err: ErrTokenNotFound, message: fmt.Sprintf("FileStorage can't find token for key '%v'", key)}
	}
	return t, nil
}

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
		return sherr{Err: ErrGeneric, message: "FileStorage failed to save tokens", wrappedErr: err}
	}

	if err := ioutil.WriteFile(f.getFilePath(), raw, 0600); err != nil {
		return sherr{Err: ErrGeneric, message: "FileStorage failed to save tokens", wrappedErr: err}
	}
	return nil
}

func (f FileStorage) loadMap() (fileStore, error) {
	data, err := ioutil.ReadFile(f.getFilePath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fileStore{}, nil
		}
		return nil, sherr{Err: ErrGeneric, message: "FileStorage failed to load file", wrappedErr: err}
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
			return nil, sherr{Err: ErrGeneric, message: "fileStore get token failed", wrappedErr: err}
		}
		var token oauth2.Token
		if err := json.Unmarshal(raw, &token); err != nil {
			return nil, sherr{Err: ErrGeneric, message: "fileStore get token failed", wrappedErr: err}
		}
		return &token, nil
	}

	return nil, sherr{Err: ErrTokenNotFound, message: fmt.Sprintf("fileStore can't find token for key '%v'", key)}
}

func (f *fileStore) setToken(key string, tok *oauth2.Token) error {
	raw, err := json.Marshal(tok)
	if err != nil {
		return sherr{Err: ErrGeneric, message: "fileStore set token failed", wrappedErr: err}
	}

	(*f)[key] = base64.StdEncoding.EncodeToString(raw)
	return nil
}
