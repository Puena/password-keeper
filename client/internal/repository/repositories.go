package repository

import (
	"github.com/Puena/password-keeper/client/config"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type Repositories struct {
	Viper   *viperRepository
	Crypto  *encryptionRepository
	Storage *storageRepository
	Device  *deviceRepository
	Sync    *syncRepository
}

func NewRepositories(db *sqlx.DB, vpr *viper.Viper, config *config.Config, logger *zap.Logger) *Repositories {
	return &Repositories{
		Viper:   NewViperRepository(vpr, config, logger),
		Crypto:  NewEncriptionRepository(config, logger),
		Storage: NewStorageRepository(db, config, logger),
		Device:  NewDeviceRepository(config, logger),
		Sync:    NewSyncRepository(config, logger),
	}
}
