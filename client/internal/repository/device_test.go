package repository

import (
	"errors"
	"testing"

	"github.com/Puena/password-keeper/client/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestExtractDeviceName(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while init config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while init logger")

	deviceRepo := NewDeviceRepository(cfg, lg)

	t.Run("extract_device_name", func(t *testing.T) {
		deviceInfo, err := deviceRepo.ExtractDeviceName()
		require.NoError(t, err, "failed while extract device name")
		require.NotNil(t, deviceInfo, "device info is nil")
		require.NotEmpty(t, deviceInfo.Name, "device name is empty")
	})
}

func TestDeviceRepositoryErrors(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while init config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while init logger")

	deviceRepo := NewDeviceRepository(cfg, lg)

	t.Run("device_repository_error", func(t *testing.T) {
		drErr := NewDeviceRepositoryError("test error", errors.New("test error"))
		assert.True(t, deviceRepo.IsDeviceRepositoryError(drErr), "error is not device repository error")
		assert.False(t, deviceRepo.IsDeviceRepositoryError(errors.New("some error")), "error is device repository error")
		assert.NotEmpty(t, drErr.Error(), "error message is empty")
	})
}
