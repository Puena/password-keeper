package repository

import (
	"errors"
	"fmt"
	"os"

	"github.com/Puena/password-keeper/client/config"
	"github.com/Puena/password-keeper/client/internal/models"
	"go.uber.org/zap"
)

type deviceRepository struct {
	logger *zap.Logger
	config *config.Config
}

type deviceRepositoryError struct {
	*baseRepositoryError
}

func (re *deviceRepositoryError) Error() string {
	return fmt.Sprintf("device repostiory error: %s %s", re.message, re.err)
}

func NewDeviceRepository(config *config.Config, logger *zap.Logger) *deviceRepository {
	return &deviceRepository{
		logger: logger,
		config: config,
	}
}

// NewDeviceRepositoryError create new device repository error.
func NewDeviceRepositoryError(message string, err error) error {
	return &deviceRepositoryError{
		newBaseRepositoryError(message, err),
	}
}

// ExtractDeviceName get host name info.
func (r *deviceRepository) ExtractDeviceName() (deviceInfo *models.DeviceInfo, err error) {
	h, err := os.Hostname()
	if err != nil {
		err = NewDeviceRepositoryError("failed while trying to get host name", err)
	}

	deviceInfo = &models.DeviceInfo{
		Name: h,
	}
	return
}

// IsDeviceRepositoryError check if it is device repository error than return it or return nil.
func (r *deviceRepository) IsDeviceRepositoryError(err error) bool {
	var drerr *deviceRepositoryError
	return errors.As(err, &drerr)
}
