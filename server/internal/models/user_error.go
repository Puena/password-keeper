package models

import "fmt"

// ErrUserModelPassword represents user model password errors.
type ErrUserModelPassword struct {
	message string
	err     error
}

// Error implements Error interface.
func (e *ErrUserModelPassword) Error() string {
	return fmt.Sprintf("user model password error: %s %s", e.message, e.err)
}

// Unwrap implements Unwrap interface.
func (e *ErrUserModelPassword) Unwrap() error {
	return e.err
}

// newErrUserModelPassword creates new user model password error.
func newErrUserModelPassword(message string, err error) error {
	return &ErrUserModelPassword{
		message: message,
		err:     err,
	}
}
