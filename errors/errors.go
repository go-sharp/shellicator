package errors

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
	case ErrProviderNotFound:
		return "shellicator: no provider found"
	case ErrProviderCfgInvalid:
		return "shellicator: invalid provider configuration"
	default:
		return "shellicator: generic error occured"
	}
}

// WithMessage returns an error with the specified message.
func (e Err) WithMessage(msg string) error {
	return &sherr{Err: e, message: msg}
}

// WithWrappedError wraps an existing error an returns a new error.
func (e Err) WithWrappedError(err error) error {
	return &sherr{Err: e, wrappedErr: err}
}

// WithMessageAndError wraps an existing error and adds a message.
func (e Err) WithMessageAndError(msg string, err error) error {
	return &sherr{Err: e, wrappedErr: err, message: msg}
}

const (
	_ Err = iota
	// ErrGeneric Generic error occured.
	ErrGeneric
	// ErrTokenNotFound a token was not found.
	ErrTokenNotFound
	// ErrProviderNotFound no oauth provider found
	ErrProviderNotFound
	// ErrProviderCfgInvalid provider configuration is invalid.
	ErrProviderCfgInvalid
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
