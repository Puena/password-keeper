package command

import (
	"bytes"
	"context"
	"testing"

	"github.com/Puena/password-keeper/client/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestAddCmd(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while init config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while init logger")

	result := new(bytes.Buffer)
	errors := new(bytes.Buffer)
	usecase := NewMockAddUsecases(t)
	cmd := NewAddCmd(lg, cfg, usecase)
	cmd.GetCommand().SetOut(result)
	cmd.GetCommand().SetErr(errors)
	cmd.ExecuteContext(context.Background())

	assert.True(t, result.Len() > 0, "failed while expected result")
	assert.True(t, errors.Len() == 0, "failed while expected no errors")
}
