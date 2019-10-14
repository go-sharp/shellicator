package shellicator

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/oauth2"
)

// Storager persists tokens for later use.
type Storager interface {
	RetrieveToken(key string) (*oauth2.Token, error)
	StoreToken(key string, token *oauth2.Token)
}

// NewAuthenticator returns a new Authenticator.
func NewAuthenticator(opts ...AuthOptions) Authenticator {
	authenticator := Authenticator{
		providers: make(map[string]oauth2.Config),
		timeout:   time.Minute * 5,
		ports:     []int{42000, 42001, 42002, 42003, 42004, 42005, 42006, 42007, 42008, 42009},
	}

	for _, fn := range opts {
		fn(&authenticator)
	}

	if authenticator.store == nil {
		authenticator.store = &MemoryStorage{}
	}

	return authenticator
}

// AuthOptions sets options for the Authenticator.
type AuthOptions func(*Authenticator)

// Authenticator handles oauth tokens for a command line application.
type Authenticator struct {
	openBrowser bool
	ports       []int
	timeout     time.Duration
	store       Storager
	providers   map[string]oauth2.Config
}

// Authenticate opens a browser windows and calls the configured oauth provider.
func (a Authenticator) Authenticate(key string) error {
	prov, ok := a.providers[key]
	if !ok {
		return fmt.Errorf("Authenticator: no provider with the given key %v found", key)
	}

	ln, port, err := getListener(a.ports)
	if err != nil {
		return err
	}

	prov.RedirectURL = fmt.Sprintf("http://localhost:%v/callback", port)

	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()

	token, err := a.handleTokenExchange(ctx, ln, prov)
	if err != nil {
		return err
	}

	a.store.StoreToken(key, token)
	return nil
}

// GetToken gets a stored oauth token.
func (a Authenticator) GetToken(key string) (*oauth2.Token, error) {
	t, err := a.store.RetrieveToken(key)
	if err != nil {
		return nil, err
	}

	return t, nil
}

// WithProvider configures an oauth provider with the specified key.
// RedirectURI will be overwritten and must not be set.
func WithProvider(key string, cfg oauth2.Config) AuthOptions {
	return func(a *Authenticator) {
		a.providers[key] = cfg
	}
}

func (a Authenticator) handleTokenExchange(ctx context.Context, ln net.Listener, cfg oauth2.Config) (*oauth2.Token, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("Authenticator: failed to create state parameter: %v", err)
	}

	state := base64.StdEncoding.EncodeToString(b)

	okCh := make(chan string)
	errCh := make(chan error)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// TODO: Implement token response handler
		rstate := r.URL.Query().Get("state")
		rcode := r.URL.Query().Get("code")
		if rstate == "" || rcode == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, http.StatusText(http.StatusBadRequest))
			errCh <- errors.New("did not receive a proper oauth response")
			return
		}

		if subtle.ConstantTimeCompare([]byte(state), []byte(rstate)) == 0 {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, http.StatusText(http.StatusForbidden))
			errCh <- errors.New("state parameter mismatch")
			return
		}

		fmt.Fprintln(w, "Successfully recevied oauth token, you may close this window.")
		okCh <- rcode
	})

	server := http.Server{Handler: mux}
	go func() {
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	defer server.Close()

	// Open browser and print Auth URL
	// TODO: Implement PKCE
	url := cfg.AuthCodeURL(state, oauth2.AccessTypeOffline)
	fmt.Println(url)

	var code string
	select {
	case code = <-okCh:
		// Do nothing
	case err := <-errCh:
		return nil, err
	case <-ctx.Done():
		return nil, errors.New("Authenticator: timeout while waiting for oauth response")
	}

	t, err := cfg.Exchange(ctx, code, oauth2.AccessTypeOffline)
	if err != nil {
		return nil, err
	}

	return t, nil
}

func getListener(ports []int) (net.Listener, int, error) {
	for _, p := range ports {
		l, err := net.Listen("tcp", "localhost:"+strconv.Itoa(p))
		if err == nil {
			return l, p, nil
		}
	}

	return nil, -1, fmt.Errorf("could not bind any of this local ports: %v", ports)
}
