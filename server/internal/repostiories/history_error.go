package repositories

import (
	"errors"
	"fmt"
)

// ErrHistoryRepository represents history repository error.
type ErrHistoryRepository struct {
	ErrRepositoryError
}

// newErrHistoryRepository create history repository error.
func newErrHistoryRepository(message string, err error) *ErrHistoryRepository {
	return &ErrHistoryRepository{
		ErrRepositoryError{
			message: message,
			error:   err,
		},
	}
}

// Error impolements Error interface.
func (e *ErrHistoryRepository) Error() string {
	return fmt.Sprintf("history %s", e.ErrRepositoryError.Error())
}

// RepositoryError check if error is history repository error, then return it, otherwise return nil.
func (r *historyRepository) RepositoryError(err error) error {
	var historyError *ErrHistoryRepository
	if errors.As(err, &historyError) {
		return err
	}

	return nil
}
