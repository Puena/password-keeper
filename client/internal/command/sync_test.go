package command

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/Puena/password-keeper/client/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestSyncCmd(t *testing.T) {

	cfg, err := config.New()
	require.NoError(t, err, "failed while init config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while init logger")

	type testArgs struct {
		input []string
	}

	type testExpected struct {
		usecaseError error
	}

	type testData struct {
		name     string
		args     testArgs
		expected testExpected
	}

	data := []testData{
		{
			name: "success_list_all_items",
			args: testArgs{
				input: []string{},
			},
			expected: testExpected{},
		},
		{
			name: "usecase_error",
			args: testArgs{
				input: []string{},
			},
			expected: testExpected{
				usecaseError: errors.New("some error"),
			},
		},
	}

	for _, tt := range data {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			syncMock := NewMockSyncUsecase(t)
			result := new(bytes.Buffer)
			errors := new(bytes.Buffer)

			defer func() {
				cmd := NewSyncCmd(syncMock, cfg, lg)
				cmd.GetCommand().SetOut(result)
				cmd.GetCommand().SetErr(errors)
				cmd.GetCommand().SetArgs(tt.args.input)
				cmd.baseCommand.GetCommand().SetOut(result)
				cmd.baseCommand.GetCommand().SetErr(errors)

				cmd.ExecuteContext(context.Background())
				if tt.expected.usecaseError != nil {
					assert.True(t, errors.Len() > 0, "failed while expecting error")
					return
				}

				assert.True(t, errors.Len() == 0, "failed while expecting result but got error")
				assert.True(t, result.Len() > 0, "failed while expecting result")
			}()

			stub := new(bytes.Buffer)
			syncMock.EXPECT().Sync(mock.Anything, stub).Return(tt.expected.usecaseError)
			if tt.expected.usecaseError != nil {
				syncMock.EXPECT().ExtractUserError(tt.expected.usecaseError).Return(tt.expected.usecaseError)
				return
			}

		})
	}
}
