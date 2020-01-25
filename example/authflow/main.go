package main

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/go-sharp/shellicator"
	serr "github.com/go-sharp/shellicator/errors"
	"github.com/go-sharp/shellicator/providers"
)

func main() {
	// You need to create a client_id and secret for the google identity platform,
	// to run this example.
	auth := shellicator.NewAuthenticator(shellicator.WithProvider("google",
		providers.NewGoogleProvider(os.Getenv("SHELLICATOR_CLIENT_ID"),
			os.Getenv("SHELLICATOR_CLIENT_SECRET"), "profile", "email", "openid")),
		shellicator.WithUseOpenBrowserFeature(true),
		shellicator.WithStore(shellicator.FileStorage{Name: ".shellicator-example"}),
		shellicator.WithCallbackTemplate(`
	<html>
	<head>
		<title>Shellicator Example</title>
		<style>
		p {
			color: blue;
			size: 24px;
		}
		</style>
	</head>
		<h1>Shellicator Example</h1>
		<p>Successfully retrieved the oauth token! You may close this window now.</p>
	</html>
	`))

	// Create a new client with the google token. If no token
	// was found, method retunrs an ErrTokenNotFound error.
	client, err := auth.NewClient(context.Background(), "google")
	if err != nil {
		if !errors.Is(err, serr.ErrTokenNotFound) {
			log.Fatal(err)
		}

		if err := auth.Authenticate("google"); err != nil {
			log.Fatal(err)
		}
	}

	// You should check for errors, but if we get this far
	// there should be a token for the client in the storage.
	client, _ = auth.NewClient(context.Background(), "google")

	// Get userinfos from the google server with the stored token.
	res, err := client.Get("https://openidconnect.googleapis.com/v1/userinfo")
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	// Error intentionally ignored
	info, _ := ioutil.ReadAll(res.Body)
	fmt.Printf("Your user infos:\n%s\n", info)
}
