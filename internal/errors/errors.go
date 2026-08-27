// Package errors implements the structured error model used across shaka.
//
// Errors carry an optional exit code so the CLI can map a failure to the
// QYVORA exit-code contract without matching on strings, and an optional
// wrapped cause so the internal system retains useful technical context even
// when the CLI renders only a friendly surface message.
package errors

import (
	"fmt"
	"os"
)

// ExitError is an error that maps to a specific process exit code.
type ExitError struct {
	Code    int
	Message string
	Cause   error
}

// NewExitError returns an error that maps to the given exit code.
func NewExitError(code int, msg string) *ExitError {
	return &ExitError{Code: code, Message: msg}
}

// WrapExitError returns an error wrapping a cause with an exit code.
func WrapExitError(code int, msg string, cause error) *ExitError {
	return &ExitError{Code: code, Message: msg, Cause: cause}
}

// Error implements the error interface.
func (e *ExitError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

// Unwrap exposes the wrapped cause for errors.Is/errors.As.
func (e *ExitError) Unwrap() error { return e.Cause }

// Fatalf prints a red error line to stderr and exits with the given code.
func Fatalf(code int, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(code)
}

// Fatalln prints a red error line to stderr and exits with the given code.
func Fatalln(code int, msg string) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", msg)
	os.Exit(code)
}
