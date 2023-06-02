package repository

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/Puena/password-keeper/client/config"
	"github.com/jmoiron/sqlx"
	"github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
)

type baseRepository struct {
	logger *zap.Logger
	config *config.Config
	db     *sqlx.DB
}

// newBaseRepository create new base repository.
func newBaseRepository(db *sqlx.DB, logger *zap.Logger, config *config.Config) *baseRepository {
	return &baseRepository{
		logger: logger,
		config: config,
		db:     db,
	}
}

// IsConfictError check if error is conflict error.
func (r *baseRepository) IsConfictError(err error) bool {
	var s3err *sqlite3.Error
	if errors.As(err, &s3err) {
		return s3err.Code == sqlite3.ErrConstraint
	}
	return false
}

// IsNotFoundError check if error is not found error.
func (r *baseRepository) IsNotFoundError(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}

type baseRepositoryError struct {
	message string
	err     error
}

func newBaseRepositoryError(message string, err error) *baseRepositoryError {
	return &baseRepositoryError{
		message: message,
		err:     err,
	}
}

// IsBaseRepositoryError chest if it is base repository error then return it or return nil.
func (r *baseRepository) IsBaseRepositoryError(err error) bool {
	var breerr *baseRepositoryError
	return errors.As(err, &breerr)
}

// Error return error message.
func (r baseRepositoryError) Error() string {
	return fmt.Sprintf("repository error: %s %s", r.message, r.err)
}

// Unwrap return wrapped error.
func (r baseRepositoryError) Unwrap() error {
	return r.err
}
