module github.com/go-sharp/shellicator

go 1.13

require (
	github.com/pkg/browser v0.0.0-20210911075715-681adbf594b8
	golang.org/x/net v0.23.0 // indirect
	golang.org/x/oauth2 v0.5.0
	google.golang.org/protobuf v1.33.0 // indirect
)

replace (
	github.com/go-sharp/shellicator => ./
	github.com/go-sharp/shellicator/storager => ./storager
)
