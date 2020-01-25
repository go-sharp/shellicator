// Package shellicator is a simple library to get oauth2 tokens for shell commands.
//
// This library opens a local http server to receive a callback from an oauth2 provider and stores the received token locally.
// It prints out the URL of the provider and if configured, opens a browser pointing to the oauth2 authcode URL.
package shellicator

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	serr "github.com/go-sharp/shellicator/errors"

	"golang.org/x/oauth2"
)

// Provider is an interface that holds the configuration for the shellicator.
type Provider interface {
	OAuth2Config() oauth2.Config
	DeviceAuthURL() string
}

// Storager persists tokens for later use.
type Storager interface {
	RetrieveToken(key string) (*oauth2.Token, error)
	StoreToken(key string, token *oauth2.Token) error
}

// PrinterCtx passed to the printer function.
type PrinterCtx struct {
	URL      string
	UserCode string
}

// VerificationURL returns the verification url and can be used to generate a QR code.
func (p PrinterCtx) VerificationURL() string {
	return fmt.Sprintf("%v?user_code=%v", p.URL, p.UserCode)
}

// IsDeviceGrant returns true if device grant flow is used
func (p PrinterCtx) IsDeviceGrant() bool {
	return p.UserCode != ""
}

// NewAuthenticator returns a new Authenticator.
func NewAuthenticator(opts ...AuthOptions) Authenticator {
	t, _ := template.New("callback").Parse("Successfully received oauth token, you may close this window now.")
	authenticator := Authenticator{
		providers:  make(map[string]provConfig),
		timeout:    time.Minute * 5,
		ports:      []int{42000, 42001, 42002, 42003, 42004, 42005, 42006, 42007, 42008, 42009},
		cbTemplate: t,
	}

	for _, fn := range opts {
		fn(&authenticator)
	}

	if len(authenticator.providers) == 0 {
		panic("shellicator: NewAuthenticator needs at least one provider option")
	}

	if authenticator.store == nil {
		authenticator.store = &MemoryStorage{}
	}

	if authenticator.printer == nil {
		authenticator.printer = defaultPrinter(authenticator.openBrowser)
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
	providers   map[string]provConfig
	listener    net.Listener
	printer     func(PrinterCtx)
	cbTemplate  *template.Template
}

// Authenticate opens a browser windows and navigates to the configured oauth provider (if configured).
// Otherwise it prints only the URL to the oauth provider.
func (a Authenticator) Authenticate(key string) error {
	prov, ok := a.providers[key]
	if !ok {
		return serr.ErrProviderNotFound.WithMessage(fmt.Sprintf("Authenticator: no provider with the given key %v found", key))
	}

	// Check requirments for all grant types
	cfg := prov.provider.OAuth2Config()
	if cfg.ClientID == "" || cfg.Endpoint.TokenURL == "" {
		return serr.ErrProviderCfgInvalid.WithMessage(
			fmt.Sprintf("Authenticator: invalid provider configuration for key %v, missing ClientID or TokenURL", key))
	}

	var token *oauth2.Token
	var err error

	if prov.useDeviceGrant {
		token, err = a.handleDeviceGrantFlow(key, prov.provider)
	} else {
		token, err = a.handleAuthFlow(key, cfg)
	}

	if err != nil {
		return err
	}

	return a.store.StoreToken(key, token)
}

// NewClient returns a new http client with a stored oauth token.
// If no valid token was found, an ErrTokenNotFound error is returned.
func (a Authenticator) NewClient(ctx context.Context, key string) (*http.Client, error) {
	if p, ok := a.providers[key]; ok {
		t, err := a.GetToken(key)
		if err != nil {
			return nil, err
		}

		c := p.provider.OAuth2Config()
		return c.Client(ctx, t), nil
	}
	return nil, serr.ErrProviderNotFound.WithMessage(fmt.Sprintf("Authenticator: no provider with the given key %v found", key))
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
func WithProvider(key string, prov Provider) AuthOptions {
	return func(a *Authenticator) {
		if prov == nil {
			panic("Authenticator: provider must not be nil")
		}
		cfg := a.providers[key]
		cfg.provider = prov
		a.providers[key] = cfg
	}
}

// WithUseDeviceGrant configures the authenticator to use the device grant flow.
func WithUseDeviceGrant(key string, useDeviceGrant bool) AuthOptions {
	return func(a *Authenticator) {
		cfg := a.providers[key]
		cfg.useDeviceGrant = useDeviceGrant
		a.providers[key] = cfg
	}
}

// WithPorts configures the Authenticator to use the specified ports.
// Default: 42000 - 42009
func WithPorts(ports ...int) AuthOptions {
	return func(a *Authenticator) {
		if len(ports) > 0 {
			a.ports = ports
		}
	}
}

// WithTimeout configures the timeout for the Authenticator.
// If timeout reached the Authenticator closes the local server
// and returns an error. Default: 5 minutes.
func WithTimeout(d time.Duration) AuthOptions {
	return func(a *Authenticator) {
		a.timeout = d
	}
}

// WithUseOpenBrowserFeature configures if a browser should automatically openend
// and navigate to the oauth AuthCodeURL. Default: false.
func WithUseOpenBrowserFeature(openBrowser bool) AuthOptions {
	return func(a *Authenticator) {
		a.openBrowser = openBrowser
	}
}

// WithUsePrinter configures to use the supplied function to print out the oauth AuthCodeURL.
// The function receives the AuthCodeURL of the chosen oauth provider.
func WithUsePrinter(printer func(ctx PrinterCtx)) AuthOptions {
	return func(a *Authenticator) {
		if printer == nil {
			panic("shellicator: WithUsePrinter expects a function not nil")
		}
		a.printer = printer
	}
}

// WithCallbackTemplate configures the authenticator to use the specified html
// for the callback page.
func WithCallbackTemplate(html string) AuthOptions {
	return func(a *Authenticator) {
		t, err := template.New("callback").Parse(html)
		if err != nil {
			panic("shellicator: WithCallbackTemplate received an invalid template: " + err.Error())
		}
		a.cbTemplate = t
	}
}

// WithStore configures the authenticator to use the provided storager
// to save and restore tokens.
func WithStore(store Storager) AuthOptions {
	return func(a *Authenticator) {
		if store == nil {
			panic("shellicator: WithStore expects a not nil Storager")
		}
		a.store = store
	}
}

func (a Authenticator) handleDeviceGrantFlow(key string, prov Provider) (*oauth2.Token, error) {
	if prov.DeviceAuthURL() == "" {
		return nil, serr.ErrProviderCfgInvalid.WithMessage(
			fmt.Sprintf("Authenticator: invalid provider configuration for key %v, missing device auth url", key))
	}

	resp, err := http.PostForm(prov.DeviceAuthURL(), url.Values{
		"client_id": {prov.OAuth2Config().ClientID},
		"scope":     {strings.Join(prov.OAuth2Config().Scopes, " ")},
	})

	if err != nil {
		return nil, serr.ErrGeneric.WithMessageAndError("Authenticator: failed to get device code", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Println(prov.OAuth2Config())
		return nil, serr.ErrGeneric.WithMessage("Authenticator: failed to get device code: " + resp.Status)
	}

	var res deviceGrantResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, serr.ErrGeneric.WithMessageAndError("Authenticator: failed to decode answer", err)
	}

	a.printer(PrinterCtx{URL: res.VerificationURI, UserCode: res.UserCode})
	return a.requestAccessToken(prov, res)
}

func (a Authenticator) requestAccessToken(prov Provider, res deviceGrantResponse) (*oauth2.Token, error) {
	interval := res.getInterval()
	timeout := time.Second * time.Duration(res.Expires)
	if timeout > a.timeout {
		timeout = a.timeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for {
		resp, err := http.PostForm(prov.OAuth2Config().Endpoint.TokenURL, url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {res.DeviceCode},
			"client_id":   {prov.OAuth2Config().ClientID},
		})

		if err != nil {
			// If the error is only temporary or timeout is reached,
			// increase the wait interval.
			if !(err.(*url.Error).Temporary() || err.(*url.Error).Timeout()) {
				return nil, serr.ErrGeneric.WithWrappedError(err)
			}
			interval *= 2
		} else {
			data, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return nil, serr.ErrGeneric.WithWrappedError(err)
			}

			// If we get a 200 status code, decode token and return it
			if resp.StatusCode == 200 {
				var token tokenJSON
				if err := json.Unmarshal(data, &token); err != nil {
					return nil, serr.ErrGeneric.WithWrappedError(err)
				}

				return &oauth2.Token{
					AccessToken:  token.AccessToken,
					TokenType:    token.TokenType,
					RefreshToken: token.RefreshToken,
					Expiry:       token.expiry(),
				}, nil
			}

			var errResp devAccessTokenErrResponse
			if err := json.Unmarshal(data, &errResp); err != nil {
				return nil, serr.ErrGeneric.WithWrappedError(err)
			}

			switch errResp.Error {
			case devTokRespSlowDown:
				interval += 5 * time.Second
			case devTokRespAuthorizationPending:
				// Do nothing and poll again
			default:
				return nil, serr.ErrGeneric.WithMessage(fmt.Sprintf("Authenticator: %v: %v ", errResp.Error, errResp.ErrorDescription))
			}
		}

		// Wait for timeout or interval elapses
		select {
		case <-time.After(interval):
			continue
		case <-ctx.Done():
			return nil, serr.ErrTimeout.WithMessage("Authenticator: timeout while waiting for oauth response")
		}
	}

}

func (a Authenticator) handleAuthFlow(key string, cfg oauth2.Config) (*oauth2.Token, error) {
	if cfg.Endpoint.AuthURL == "" || cfg.Endpoint.TokenURL == "" {
		return nil, serr.ErrProviderCfgInvalid.WithMessage(fmt.Sprintf("Authenticator: invalid provider configuration for key %v", key))
	}

	ln, port, err := getListener(a.ports)
	if err != nil {
		return nil, err
	}

	cfg.RedirectURL = fmt.Sprintf("http://localhost:%v/callback", port)

	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()

	return a.handleTokenExchange(ctx, ln, cfg)
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

		a.cbTemplate.Execute(w, nil)
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
	a.printer(PrinterCtx{URL: url})
	if a.openBrowser {
		openURL(url)
	}

	var code string
	select {
	case code = <-okCh:
		// Do nothing
	case err := <-errCh:
		return nil, err
	case <-ctx.Done():
		return nil, serr.ErrTimeout.WithMessage("Authenticator: timeout while waiting for oauth response")
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

	return nil, -1, fmt.Errorf("could not bind any of these local ports: %v", ports)
}

func defaultPrinter(openBrowser bool) func(PrinterCtx) {
	return func(ctx PrinterCtx) {
		if ctx.IsDeviceGrant() {
			fmt.Printf("Open your browser and navigate to the following url: '%v'\nEnter this code: '%v'\n", ctx.URL, ctx.UserCode)
			return
		}

		if openBrowser {
			fmt.Printf("If your browser doesn't open automatically, navigate to the following url and authenticate yourself:\n%v\n", ctx.URL)
			return
		}

		fmt.Printf("Open your browser and navigate to the following url to authenticate yourself:\n%v\n", ctx.URL)
	}
}
