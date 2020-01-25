package providers

import "golang.org/x/oauth2"

// NewGoogleProvider creates a new ProviderInfo for the google oauth endpoint.
func NewGoogleProvider(clientID, clientSecret string, scopes ...string) *ProviderInfo {
	if len(scopes) == 0 {
		scopes = append(scopes, "openid")
	}

	return &ProviderInfo{
		config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scopes:       scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:   "https://accounts.google.com/o/oauth2/auth",
				TokenURL:  "https://oauth2.googleapis.com/token",
				AuthStyle: oauth2.AuthStyleAutoDetect,
			},
		},
		deviceAuthURL: "https://oauth2.googleapis.com/device/code",
	}

}
