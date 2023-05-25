package repository

import (
	"errors"
	"fmt"

	"github.com/Puena/password-keeper/client/config"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

const (
	loginFlag = "login"
	tokenFlag = "token"
)

type viperRepositoryError struct {
	*baseRepositoryError
}

func newViperRepositoryError(message string, err error) *viperRepositoryError {
	return &viperRepositoryError{
		newBaseRepositoryError(message, err),
	}
}

// Error implements Error interface.
func (e viperRepositoryError) Error() string {
	return fmt.Sprintf("viper respository error: %s, %s", e.message, e.err)
}

type viperRepository struct {
	config *config.Config
	logger *zap.Logger
	viper  *viper.Viper
}

func NewViperRepository(viper *viper.Viper, config *config.Config, logger *zap.Logger) *viperRepository {
	return &viperRepository{
		config: config,
		logger: logger,
		viper:  viper,
	}
}

// SetLogin save login to viper.
func (r *viperRepository) SetLogin(login string) error {
	r.viper.Set(loginFlag, login)
	return r.writeToConfig()
}

// GetLogin get login from viper.
func (r *viperRepository) GetLogin() string {
	return r.viper.GetString(loginFlag)
}

// SetToken save token to viper and write config.
func (r *viperRepository) SetToken(token string) error {
	r.viper.Set(tokenFlag, token)
	return r.writeToConfig()
}

// GetToken get token from viper.
func (r *viperRepository) GetToken() string {
	return r.viper.GetString(tokenFlag)
}

// writeToConfig write viper to config file.
func (r *viperRepository) writeToConfig() error {
	err := r.viper.WriteConfig()
	if err != nil {
		return newViperRepositoryError("failed while writing to config", err)
	}
	return nil
}

// IsWriteConfigError check if error is write config error.
func (r *viperRepository) IsWriteConfigError(err error) bool {
	var vrerr *viperRepositoryError
	return errors.As(err, &vrerr)
}
