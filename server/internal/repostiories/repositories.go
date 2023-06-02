package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/Puena/password-keeper/server/config"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"
)

type pgxInterface interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Begin(ctx context.Context) (pgx.Tx, error)
}

type Repositories struct {
	Token   *tokenRepository
	Users   *usersRepository
	Chests  *chestsRepository
	History *historyRepository
}

func New(pgx pgxInterface, config *config.Config, logger *zap.Logger) *Repositories {
	return &Repositories{
		Token:   NewTokenRepository(config, logger),
		Users:   NewUsersRepository(pgx, config, logger),
		Chests:  NewChestRepository(pgx, config, logger),
		History: NewHistoryRepository(pgx, config, logger),
	}
}

type repository struct {
	config *config.Config
	logger *zap.Logger
}

func newRepository(config *config.Config, logger *zap.Logger) repository {
	return repository{
		config: config,
		logger: logger,
	}
}

type pgRepository struct {
	repository
	pg pgxInterface
}

func newPgRepository(pg pgxInterface, config *config.Config, logger *zap.Logger) pgRepository {
	return pgRepository{
		repository: newRepository(config, logger),
		pg:         pg,
	}
}

type ErrRepositoryError struct {
	message string
	error   error
}

// Error implements Error interface.
func (e *ErrRepositoryError) Error() string {
	return fmt.Sprintf("repository error: %s %s", e.message, e.error)
}

// Unwrap implaments Unwrap interface.
func (e *ErrRepositoryError) Unwrap() error {
	return e.error
}

// RepositoryError check base case of error.
func (r *repository) RepositoryError(err error) error {
	var repoError *ErrRepositoryError
	if errors.As(err, &repoError) {
		return err
	}
	return nil
}

// NotFoundError check if error is ErrNoRows then returns it if doesn't return nil.
func (r *pgRepository) NotFoundError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	return nil
}

// ConflictError check if error is 23505 pgx code.
func (r pgRepository) ConflictError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
		return err
	}
	return nil
}
