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
	"math"
	"net"
	"net/http"
	"strconv"
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

	var token *oauth2.Token
	var err error

	if prov.useDeviceGrant {
		token, err = a.handleDeviceGrantFlow(key, prov.provider)
	} else {
		token, err = a.handleAuthFlow(key, prov.provider.OAuth2Config())
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

	resp, err := http.Get(prov.DeviceAuthURL())
	if err != nil {
		return nil, serr.ErrGeneric.WithMessageAndError("Authenticator: failed to get device code", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, serr.ErrGeneric.WithMessage("Authenticator: failed to get device code: " + resp.Status)
	}

	var res deviceGrantResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, serr.ErrGeneric.WithMessageAndError("Authenticator: failed to decode answer", err)
	}

	a.printer(PrinterCtx{URL: res.VerificationURI, UserCode: res.UserCode})
	for {
		http.Get
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

	return nil, -1, fmt.Errorf("could not bind any of these local ports: %v", ports)
}

func defaultPrinter(openBrowser bool) func(PrinterCtx) {
	return func(ctx PrinterCtx) {
		if ctx.IsDeviceGrant() {
			fmt.Printf("Open your browser and navigate to the following url and enter code '%v':\n%v\n", ctx.UserCode, ctx.URL)
			return
		}

		if openBrowser {
			fmt.Printf("If your browser doesn't open automatically, navigate to the following url and authenticate yourself:\n%v\n", ctx.URL)
			return
		}

		fmt.Printf("Open your browser and navigate to the following url to authenticate yourself:\n%v\n", ctx.URL)
	}
}

// provConfig holds the provider configuration.
type provConfig struct {
	provider       Provider
	useDeviceGrant bool
}

// deviceGrantResponse is the oauth2 device grant response see https://tools.ietf.org/html/rfc8628#section-3.2
type deviceGrantResponse struct {
	DeviceCode              string `json:"device_code,omitempty"`
	UserCode                string `json:"user_code,omitempty"`
	VerificationURI         string `json:"verification_uri,omitempty"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	Expires                 int    `json:"expires_in,omitempty"`
	Interval                int    `json:"interval,omitempty"`
}

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
