module github.com/go-sharp/shellicator

go 1.25.0

require (
	github.com/pkg/browser v0.0.0-20210911075715-681adbf594b8
	golang.org/x/oauth2 v0.5.0
)

require (
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
)

replace (
	github.com/go-sharp/shellicator => ./
	github.com/go-sharp/shellicator/storager => ./storager
)
