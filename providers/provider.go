package providers

import (
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
)

func NewProvider(clientID, clientSecret, oidcDiscoverURL string, scopes ...string) *ProviderInfo {
	if len(scopes) == 0 {
		scopes = append(scopes, "openid")
	}

	cfg, err := getWellknownConfiguration(oidcDiscoverURL)
	if err != nil {
		panic(err)
	}

	return &ProviderInfo{
		config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scopes:       scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:   cfg.AuthURL,
				TokenURL:  cfg.TokenURL,
				AuthStyle: oauth2.AuthStyleAutoDetect,
			},
		},
		deviceAuthURL: cfg.DeviceAuthURL,
	}
}

// ProviderInfo contains all required oauth2 information for the shellicator.
type ProviderInfo struct {
	config        oauth2.Config
	deviceAuthURL string
}

// OAuth2Config returns the oauth2 configuration.
func (p ProviderInfo) OAuth2Config() oauth2.Config {
	return p.config
}

// DeviceAuthURL returns the device grant authorization url.
func (p ProviderInfo) DeviceAuthURL() string {
	return p.deviceAuthURL
}

type wellknowConfiguration struct {
	AuthURL       string `json:"authorization_endpoint,omitempty"`
	TokenURL      string `json:"token_endpoint,omitempty"`
	DeviceAuthURL string `json:"device_authorization_endpoint,omitempty"`
}

func getWellknownConfiguration(url string) (cfg wellknowConfiguration, err error) {
	res, err := http.Get(url)
	if err != nil {
		return cfg, err
	}

	if res.StatusCode < 200 || res.StatusCode > 299 {
		return cfg, fmt.Errorf("failed to fetch well-known openid configuration from '%v': status %v", url, res.Status)
	}
	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&cfg)

	return cfg, err
}
