package main

import (
	"fmt"

	"github.com/go-sharp/shellicator"
	"github.com/go-sharp/shellicator/providers"
)

func main() {
	auth := shellicator.NewAuthenticator(shellicator.WithProvider("google",
		providers.NewGoogleProvider("935256488604-ib4ju6dbif58kkq6ur3eq3bgq1pkamjl.apps.googleusercontent.com",
			"FX1fCSiz9zfgPtjV7t2UFeN5")))

	fmt.Println(auth.Authenticate("google"))
	fmt.Println(auth.GetToken("google"))
}
