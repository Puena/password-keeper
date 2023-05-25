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

func TestVersionCmd(t *testing.T) {

	cfg, err := config.New()
	require.NoError(t, err, "failed while init config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while init logger")

	type testArgs struct {
		input []string
	}

	type testExpected struct {
	}

	type testData struct {
		name     string
		args     testArgs
		expected testExpected
	}

	data := []testData{
		{
			name: "success_version_extraction",
			args: testArgs{
				input: []string{},
			},
			expected: testExpected{},
		},
	}

	for _, tt := range data {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			result := new(bytes.Buffer)
			errors := new(bytes.Buffer)

			defer func() {
				cmd := NewVersionCmd(lg, cfg)
				cmd.GetCommand().SetOut(result)
				cmd.GetCommand().SetErr(errors)
				cmd.GetCommand().SetArgs(tt.args.input)
				cmd.baseCommand.GetCommand().SetOut(result)
				cmd.baseCommand.GetCommand().SetErr(errors)

				cmd.ExecuteContext(context.Background())

				assert.True(t, errors.Len() == 0, "failed while expecting result but got error")
				assert.True(t, result.Len() > 0, "failed while expecting result")
			}()

		})
	}
}
