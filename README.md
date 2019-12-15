# shellicator

A simple library to get oauth2 tokens for shell commands.

This library opens a local http server to receive a callback from an oauth2 provider and stores the received token locally. It prints out the URL of the provider and if configured, opens a browser pointing to the oauth2 authcode URL.

For a working example: [Example](./example/main.go)

## Releases
Release 1.0.0
- Initial release 

## Minimal Example

Usage:

```go
package main
import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/go-sharp/shellicator"
	"github.com/go-sharp/shellicator/providers"
)

func main() {
    // You can use any oauth2.Config you like. Important use scopes that
    // tells the provider to return a refresh token.
    // WithProvider is the only required option.
	auth := shellicator.NewAuthenticator(shellicator.WithProvider("google",
		providers.NewGoogleProvider(os.Getenv("SHELLICATOR_CLIENT_ID"),
            os.Getenv("SHELLICATOR_CLIENT_SECRET"))))

    // Now you can request a token. Per default this method will print out
    // an URL to the oauth2 provider. You can use options to open a browser
    // automatically. This call blocks until a answer is received (Default Timeout 5min).
    // The authentication is successfully if no error is returned.
    if err := auth.Authenticate("google"); err != nil {
			log.Fatal(err)
    }

    // Now you can get a client that uses the received token
    // and automatically refresh it if necessary.
    client, _ = auth.NewClient(context.Background(), "google")
    // Do something with the client

    // Or you get the received token with this call.
    token, _ = auth.GetToken("google")
    // Use the token
}
```

> Per default tokens are stored in the volatile `MemoryStorage`. If persistence is required, use the `FileStorage` or implement your own `Storager`.
