package providers

import "golang.org/x/oauth2"

// NewGoogleProvider creates a new oauth2.Config for the google oauth endpoint.
func NewGoogleProvider(clientID, clientSecret string, scopes ...string) oauth2.Config {
	if len(scopes) == 0 {
		scopes = append(scopes, "openid")
	}

	return oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://accounts.google.com/o/oauth2/auth",
			TokenURL:  "https://oauth2.googleapis.com/token",
			AuthStyle: oauth2.AuthStyleAutoDetect,
		},
	}

}
