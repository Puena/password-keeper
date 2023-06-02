package repositories

import (
	"errors"
	"fmt"
)

// ErrTokenRepository represent repository errors.
type ErrTokenRepository struct {
	ErrRepositoryError
}

func (e *ErrTokenRepository) Error() string {
	return fmt.Sprintf("token %s", e.ErrRepositoryError.Error())
}

// newErrTokenRepository create new [ErrTokenRepository] error.
func newErrTokenRepository(message string, err error) error {
	return &ErrTokenRepository{
		ErrRepositoryError{
			message: message,
			error:   err,
		},
	}
}

// RepositoryError check that error is token repository error then return it, otherwise returns nil.
func (r *tokenRepository) RepositoryError(err error) error {
	var tokenError *ErrTokenRepository
	if exists := errors.As(err, &tokenError); exists {
		return err
	}

	return nil
}
