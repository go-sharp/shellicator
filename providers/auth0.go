package providers

import (
	"strings"

	"golang.org/x/oauth2"
)

// NewAuth0Provider creates a new ProviderInfo for the auth0 endpoints.
func NewAuth0Provider(clientID, clientSecret, endpointURL string, scopes ...string) *ProviderInfo {
	if len(scopes) == 0 {
		scopes = append(scopes, "openid")
	}
	scopes = append(scopes, "offline_access")

	endpointURL = strings.TrimSuffix(endpointURL, "/")

	return &ProviderInfo{
		config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scopes:       scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:   endpointURL + "/authorize",
				TokenURL:  endpointURL + "/oauth/token",
				AuthStyle: oauth2.AuthStyleAutoDetect,
			},
		},
		deviceAuthURL: endpointURL + "/oauth/device/code",
	}
}
