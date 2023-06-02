package command

import (
	"bytes"
	"context"
	"testing"

	"github.com/Puena/password-keeper/client/config"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestConfigCmd(t *testing.T) {

	cfg, err := config.New()
	require.NoError(t, err, "failed while init config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while init logger")

	defer func() {
		viper.Reset()
	}()

	t.Run("set_login", func(t *testing.T) {
		result := new(bytes.Buffer)
		errors := new(bytes.Buffer)

		cmd := NewConfigCmd(lg, cfg)
		cmd.GetCommand().SetOut(result)
		cmd.GetCommand().SetErr(errors)
		cmd.GetCommand().SetArgs([]string{"-l some@login.ru"})

		cmd.ExecuteContext(context.Background())

		assert.True(t, errors.Len() == 0, "failed while expecting result but got error")
		assert.True(t, result.Len() > 0, "failed while expecting result")

	})

	t.Run("show_login", func(t *testing.T) {
		result := new(bytes.Buffer)
		errors := new(bytes.Buffer)

		cmd := NewConfigCmd(lg, cfg)
		cmd.GetCommand().SetOut(result)
		cmd.GetCommand().SetErr(errors)
		cmd.GetCommand().SetArgs([]string{"-s"})

		cmd.ExecuteContext(context.Background())

		assert.True(t, errors.Len() == 0, "failed while expecting result but got error")
		assert.True(t, result.Len() > 0, "failed while expecting result")

	})
}
