package providers

import (
	"strings"

	"golang.org/x/oauth2"
)

// NewAuth0Provider creates a new oauth2.Config for the auth0 endpoints.
func NewAuth0Provider(clientID, clientSecret, endpointURL string, scopes ...string) oauth2.Config {
	if len(scopes) == 0 {
		scopes = append(scopes, "openid")
	}
	scopes = append(scopes, "offline_access")

	endpointURL = strings.TrimSuffix(endpointURL, "/")

	return oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:   endpointURL + "/authorize",
			TokenURL:  endpointURL + "/oauth/token",
			AuthStyle: oauth2.AuthStyleAutoDetect,
		},
	}
}
