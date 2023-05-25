package usecases

import (
	"context"

	"github.com/Puena/password-keeper/server/config"
	"github.com/Puena/password-keeper/server/internal/models"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// UsersRepository represents actions required from users repository for user operations.
//
//go:generate mockery --name UsersRepository
type UsersRepository interface {
	InsertUser(ctx context.Context, data *models.UserModel) (*uuid.UUID, error)
	SelectUserByID(ctx context.Context, id uuid.UUID) (*models.UserModel, error)
	SelectUserByLogin(ctx context.Context, login string) (*models.UserModel, error)

	// Errors
	ConflictError(err error) error
	NotFoundError(err error) error
	RepositoryError(err error) error
}

// TokenRepository represents actions required from users repository for token opeations.
//
//go:generate mockery --name TokenRepository
type TokenRepository interface {
	GenerateToken(ctx context.Context, userID uuid.UUID) (string, error)
	ValidateToken(ctx context.Context, token string) (*uuid.UUID, error)

	// Errors
	RepositoryError(err error) error
}

// ChestRepository represents actions required for chest operations.
//
//go:generate mockery --name ChestRepository
type ChestRepository interface {
	SelectChestByID(ctx context.Context, chestID string, userID uuid.UUID) (*models.Chest, *models.History, error)
	UpsertChest(ctx context.Context, chest *models.Chest, history *models.History) error
	DeleteChest(ctx context.Context, history *models.History) error

	// Error
	RepositoryError(err error) error
	NotAffectedError(err error) error
	NotFoundError(err error) error
	ConflictError(err error) error
}

// HistoryRepository represents actions required for history operations.
//
//go:generate mockery --name HistoryRepository
type HistoryRepository interface {
	SelectUserChestsLastHistory(ctx context.Context, userID uuid.UUID) ([]*models.History, error)

	// Error
	RepositoryError(err error) error
	NotFoundError(err error) error
}

//go:generate mockery --name Repositories
type Repositories interface {
	Users() UsersRepository
	Token() TokenRepository
	Chests() ChestRepository
	History() HistoryRepository
}

type keeperUseCases struct {
	usersRepository   UsersRepository
	tokenRepository   TokenRepository
	chestsRepository  ChestRepository
	historyRepository HistoryRepository
	config            *config.Config
	logger            *zap.Logger
}

// New initializing keeperUseCases.
func New(
	repo Repositories,
	config *config.Config,
	logger *zap.Logger) *keeperUseCases {
	return &keeperUseCases{
		usersRepository:   repo.Users(),
		tokenRepository:   repo.Token(),
		chestsRepository:  repo.Chests(),
		historyRepository: repo.History(),
		config:            config,
		logger:            logger,
	}
}
