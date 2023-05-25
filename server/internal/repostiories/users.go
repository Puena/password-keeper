package repositories

import (
	"context"

	"github.com/Puena/password-keeper/server/config"
	"github.com/Puena/password-keeper/server/internal/models"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// userRepository represents users repostiory struct.
type usersRepository struct {
	pgRepository
}

// InitUserRepository fuction for initialization users repository.
func NewUsersRepository(pg pgxInterface, config *config.Config, logger *zap.Logger) *usersRepository {
	return &usersRepository{
		pgRepository: newPgRepository(pg, config, logger),
	}
}

// InserUser insert a user into database, than return inserted user id or error.
func (r *usersRepository) InsertUser(ctx context.Context, data *models.UserModel) (*uuid.UUID, error) {

	const insertQuery = "INSERT INTO users (id, login, password, created_at) VALUES ($1, $2, $3, $4) RETURNING id"

	row := r.pg.QueryRow(ctx, insertQuery, &data.Id, &data.Login, &data.PasswordHash, &data.CreatedAt)

	var insertedID uuid.UUID
	err := row.Scan(&insertedID)
	if err != nil {
		return nil, newErrUserRepository("failed when scan userID", err)
	}

	return &insertedID, nil
}

// SelectUserByID select a user from database by id, than return user data or error.
func (r *usersRepository) SelectUserByID(ctx context.Context, id uuid.UUID) (*models.UserModel, error) {

	const selectQuery = "SELECT id, login, password, created_at FROM users WHERE id = $1"

	row := r.pg.QueryRow(ctx, selectQuery, &id)

	var result models.UserModel
	err := row.Scan(
		&result.Id,
		&result.Login,
		&result.PasswordHash,
		&result.CreatedAt,
	)
	if err != nil {
		return nil, newErrUserRepository("failed when scan to user model", err)
	}

	return &result, nil
}

// SelectUserByLogin select one user from database by login and returns user data otherwise nil.
func (r *usersRepository) SelectUserByLogin(ctx context.Context, login string) (*models.UserModel, error) {

	const selectQuery = "SELECT id, login, password, created_at FROM users WHERE login = $1"

	row := r.pg.QueryRow(ctx, selectQuery, &login)

	var result models.UserModel
	err := row.Scan(
		&result.Id,
		&result.Login,
		&result.PasswordHash,
		&result.CreatedAt,
	)
	if err != nil {
		return nil, newErrUserRepository("failed when scan to user model", err)
	}

	return &result, nil
}
