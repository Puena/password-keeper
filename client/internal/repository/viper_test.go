package repository

import (
	"errors"
	"testing"

	"github.com/Puena/password-keeper/client/config"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestViperRepository(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while initializing config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")
	v := viper.GetViper()

	t.Run("get/set_login", func(t *testing.T) {

		vr := NewViperRepository(v, cfg, lg)

		err := vr.SetLogin("someLogin")
		require.NoError(t, err, "failed while setting login")

		login := vr.GetLogin()
		assert.NotEmpty(t, login, "login is empty")
	})

	t.Run("get/set token", func(t *testing.T) {

		vr := NewViperRepository(v, cfg, lg)

		err := vr.SetToken("someLogin")
		require.NoError(t, err, "failed while setting login")

		token := vr.GetToken()
		assert.NotEmpty(t, token, "token is empty")
	})

	t.Run("viper_repository_error", func(t *testing.T) {
		vr := NewViperRepository(v, cfg, lg)
		vrErr := newViperRepositoryError("someMessage", errors.New("someError"))

		assert.True(t, vr.IsWriteConfigError(vrErr), "viper_repository_error is not write config error")
		assert.False(t, vr.IsWriteConfigError(errors.New("someError")), "someError is write config error")
		assert.NotEmpty(t, vrErr.Error(), "message is empty")
	})
}
