package main

import (
	"fmt"

	"github.com/go-sharp/shellicator"
	"github.com/go-sharp/shellicator/providers"
)

func main() {
	auth := shellicator.NewAuthenticator(shellicator.WithProvider("google",
		providers.NewGoogleProvider("<Client ID>",
			"<Client ID>")))

	fmt.Println(auth.Authenticate("google"))
	fmt.Println(auth.GetToken("google"))
}
