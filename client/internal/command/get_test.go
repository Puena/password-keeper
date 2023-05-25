package command

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/Puena/password-keeper/client/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestGetCmd(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while init config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while init logger")

	result := new(bytes.Buffer)
	errors := new(bytes.Buffer)
	usecase := NewMockGetUsecases(t)
	cmd := NewGetCmd(usecase, cfg, lg)
	cmd.GetCommand().SetOut(result)
	cmd.GetCommand().SetErr(errors)
	cmd.ExecuteContext(context.Background())

	fmt.Println(result.String())
	assert.True(t, result.Len() > 0, "failed while expected result")
	assert.True(t, errors.Len() == 0, "failed while expected no errors")
}
