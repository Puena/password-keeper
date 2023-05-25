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

func TestDeleteCmd(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while init config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while init logger")

	type testArgs struct {
		input        []string
		name         string
		lockPassword string
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
			name: "success",
			args: testArgs{
				input: []string{
					"sberbank",
				},
				name:         "sberbank",
				lockPassword: "some-password",
			},
			expected: testExpected{},
		},
		{
			name: "usecase_error",
			args: testArgs{
				input: []string{
					"sberbank",
				},
				name:         "sberbank",
				lockPassword: "some-password",
			},
			expected: testExpected{
				usecaseError: errors.New("some error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			mockUsecase := NewMockDeleteUsecases(t)

			defer func() {
				result := new(bytes.Buffer)
				errors := new(bytes.Buffer)
				in := new(bytes.Buffer)
				in.WriteString(tt.args.lockPassword + "\n")

				cmd := NewDeleteCmd(mockUsecase, cfg, lg)
				cmd.GetCommand().SetOut(result)
				cmd.GetCommand().SetErr(errors)
				cmd.GetCommand().SetIn(in)
				cmd.GetCommand().SetArgs(tt.args.input)
				cmd.ExecuteContext(context.Background())

				if tt.expected.usecaseError != nil {
					assert.True(t, errors.Len() > 0, "failed while expected errors")
					return
				}

				assert.True(t, errors.Len() == 0, "failed while expected no errors")
				assert.True(t, result.Len() > 0, "failed while expected result")
			}()

			mockUsecase.EXPECT().DeleteChest(mock.Anything, tt.args.name, tt.args.lockPassword).Return(tt.expected.usecaseError)
			if tt.expected.usecaseError != nil {
				mockUsecase.EXPECT().ExtractUserError(tt.expected.usecaseError).Return(tt.expected.usecaseError)
				return
			}
		})
	}

}
