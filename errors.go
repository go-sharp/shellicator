package shellicator

import "fmt"

// Err is a shellicator specific error.
type Err int

// Is implementation of errors.Is
func (e Err) Is(err error) bool {
	if cerr, ok := err.(Err); ok {
		return cerr == e
	}
	return false
}

func (e Err) Error() string {
	switch e {
	case ErrTokenNotFound:
		return "shellicator: token not found"
	default:
		return "shellicator: generic error occured"
	}
}

const (
	_ Err = iota
	// ErrGeneric Generic error occured.
	ErrGeneric
	// ErrTokenNotFound A token was not found.
	ErrTokenNotFound
	// ErrProviderNotFound No valid oauth provider found
	ErrProviderNotFound
)

type sherr struct {
	Err
	message    string
	wrappedErr error
}

func (e sherr) Error() string {
	if e.message == "" && e.wrappedErr == nil {
		return e.Err.Error()
	}
	if e.wrappedErr != nil {
		return fmt.Sprintf("shellicator: %v : %v", e.message, e.wrappedErr)
	}
	return "shellicator: " + e.message
}

func (e sherr) Unwrap() error {
	return e.wrappedErr
}
