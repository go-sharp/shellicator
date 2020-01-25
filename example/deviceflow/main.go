package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/go-sharp/shellicator"
	"github.com/go-sharp/shellicator/providers"
)

func main() {
	// You need to create a client_id for your identity platform
	// and enable the device grant type, to run this example.
	auth := shellicator.NewAuthenticator(
		shellicator.WithProvider("auth0", providers.NewProvider(
			os.Getenv("SHELLICATOR_CLIENT_ID"), "", os.Getenv("SHELLICATOR_OIDC_DISCOVERY"), "openid", "profile", "email")),
		shellicator.WithUseDeviceGrant("auth0", true),
	)

	if err := auth.Authenticate("auth0"); err != nil {
		log.Fatal(err)
	}

	// You should check for errors, but if we get this far
	// there should be a token for the client in the storage.
	client, _ := auth.NewClient(context.Background(), "auth0")

	res, err := client.Get(os.Getenv("SHELLICATOR_USERPROFILE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	// Error intentionally ignored
	info, _ := ioutil.ReadAll(res.Body)
	fmt.Printf("Your user infos:\n%s\n", info)
}
