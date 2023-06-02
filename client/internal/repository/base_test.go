package repository

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Puena/password-keeper/client/config"
	"github.com/jmoiron/sqlx"
	"github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func Test_BaseRepository_Errors(t *testing.T) {
	cfg := &config.Config{}
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")

	t.Run("conflict_error", func(t *testing.T) {
		mockDB, _, err := sqlmock.New()
		require.NoError(t, err, "failed while initializing sqlmock")
		db := sqlx.NewDb(mockDB, "sqlmock")
		repository := newBaseRepository(db, lg, cfg)

		assert.True(t, repository.IsConfictError(&sqlite3.Error{Code: sqlite3.ErrConstraint}))
		assert.False(t, repository.IsConfictError(errors.New("some error")))
	})

	t.Run("not_found_error", func(t *testing.T) {
		mockDB, _, err := sqlmock.New()
		require.NoError(t, err, "failed while initializing sqlmock")
		db := sqlx.NewDb(mockDB, "sqlmock")
		repository := newBaseRepository(db, lg, cfg)

		assert.True(t, repository.IsNotFoundError(sql.ErrNoRows))
		assert.False(t, repository.IsNotFoundError(errors.New("some error")))
	})

	t.Run("base_repository_error", func(t *testing.T) {
		mockDB, _, err := sqlmock.New()
		require.NoError(t, err, "failed while initializing sqlmock")
		db := sqlx.NewDb(mockDB, "sqlmock")
		repository := newBaseRepository(db, lg, cfg)

		brErr := newBaseRepositoryError("some message", errors.New("some error"))
		assert.True(t, repository.IsBaseRepositoryError(brErr))
		assert.False(t, repository.IsBaseRepositoryError(errors.New("some error")))
		assert.NotEmpty(t, brErr.Error(), "failed while getting error message")
		assert.Error(t, brErr.Unwrap(), "failed while unwrapping error")
	})
}
