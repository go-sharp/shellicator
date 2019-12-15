module github.com/go-sharp/shellicator

go 1.13

require (
	github.com/pkg/browser v0.0.0-20180916011732-0a3d74bf9ce4
	golang.org/x/oauth2 v0.0.0-20191202225959-858c2ad4c8b6
)

replace (
	github.com/go-sharp/shellicator => ./
	github.com/go-sharp/shellicator/storager => ./storager
)
