package repositories

import (
	"errors"
	"fmt"
)

var ErrChestsRepositoryNotAffected = errors.New("operations not affected")

// ErrChestsRepository represents chest repository errors.
type ErrChestsRepository struct {
	ErrRepositoryError
}

func newErrChestsRepositoryError(message string, err error) error {
	return &ErrChestsRepository{
		ErrRepositoryError: ErrRepositoryError{
			message: message,
			error:   err,
		},
	}
}

// Error implements Error interface
func (e *ErrChestsRepository) Error() string {
	return fmt.Sprintf("chests %s", e.ErrRepositoryError.Error())
}

// RepositoryError check if error is [ErrChestsRepository] then return in, if doesn't return nil.
func (e *chestsRepository) RepositoryError(err error) error {
	var chestsError *ErrChestsRepository
	if errors.As(err, &chestsError) {
		return err
	}

	return nil
}

// NotAffectedError check if error is [ErrChestsRepositoryNotAffected], then return error or nil.
func (e *chestsRepository) NotAffectedError(err error) error {
	if errors.Is(err, ErrChestsRepositoryNotAffected) {
		return err
	}

	return nil
}
