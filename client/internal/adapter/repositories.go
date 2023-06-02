package adapter

import (
	"github.com/Puena/password-keeper/client/internal/repository"
	"github.com/Puena/password-keeper/client/internal/usecase"
)

type UsecasesRepositoriesAdapter struct {
	repositories *repository.Repositories
}

func NewUsecaesRepositoriesAdapter(repositories *repository.Repositories) *UsecasesRepositoriesAdapter {
	return &UsecasesRepositoriesAdapter{
		repositories: repositories,
	}
}

func (a *UsecasesRepositoriesAdapter) Viper() usecase.ViperRepository {
	return a.repositories.Viper
}

func (a *UsecasesRepositoriesAdapter) Crypto() usecase.EncryptionRepository {
	return a.repositories.Crypto
}

func (a *UsecasesRepositoriesAdapter) Storage() usecase.StorageRepostiory {
	return a.repositories.Storage
}

func (a *UsecasesRepositoriesAdapter) Device() usecase.DeviceRepository {
	return a.repositories.Device
}

func (a *UsecasesRepositoriesAdapter) Sync() usecase.SyncRepository {
	return a.repositories.Sync
}
