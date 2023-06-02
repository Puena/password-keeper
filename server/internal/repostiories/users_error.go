package repositories

import (
	"errors"
	"fmt"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
)

// errUserRepository represents user repostiory errors.
type errUserRepository struct {
	ErrRepositoryError
}

func (e *errUserRepository) Error() string {
	return fmt.Sprintf("user %s", e.ErrRepositoryError.Error())
}

func newErrUserRepository(message string, err error) *errUserRepository {
	return &errUserRepository{
		ErrRepositoryError{
			message: message,
			error:   err,
		},
	}
}

// ConflictError check if error has UniqueViolation code then returns an error if doesn't return nil.
func (r *usersRepository) ConflictError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
		return err
	}
	return nil
}

// RepositoryError check that an error is [ErrUserRepository] then returns it if doesn't return nil.
func (r *usersRepository) RepositoryError(err error) error {
	var repositoryError *errUserRepository
	if exists := errors.As(err, &repositoryError); exists {
		return err
	}

	return nil
}
