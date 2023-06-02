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

func TestAddFileCmd(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while init config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while init logger")

	type testArgs struct {
		input        []string
		name         string
		path         string
		lockPassword string
	}

	type testExpected struct {
		file          []byte
		usecaseError  error
		readFileError error
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
				input:        []string{"some-name", "-p some/path"},
				name:         "some-name",
				path:         "some/path",
				lockPassword: "some-password",
			},
			expected: testExpected{
				file: []byte("some-file"),
			},
		},
		{
			name: "read_file_error",
			args: testArgs{
				input:        []string{"some-name", "-p some/path"},
				name:         "some-name",
				path:         "some/path",
				lockPassword: "some-password",
			},
			expected: testExpected{
				file:          []byte("some-file"),
				readFileError: errors.New("some-error"),
			},
		},
		{
			name: "usecase_error",
			args: testArgs{
				input:        []string{"some-name", "-p some/path"},
				name:         "some-name",
				path:         "some/path",
				lockPassword: "some-password",
			},
			expected: testExpected{
				file:         []byte("some-file"),
				usecaseError: errors.New("some-error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {

			mockUsecase := NewMockAddFileUsecase(t)

			defer func() {
				result := new(bytes.Buffer)
				errors := new(bytes.Buffer)
				in := new(bytes.Buffer)
				in.WriteString(tt.args.lockPassword + "\n")

				cmd := NewAddFileCmd(mockUsecase, cfg, lg)
				cmd.GetCommand().SetOut(result)
				cmd.GetCommand().SetErr(errors)
				cmd.GetCommand().SetIn(in)
				cmd.GetCommand().SetArgs(tt.args.input)
				cmd.ExecuteContext(context.Background())

				if tt.expected.usecaseError != nil ||
					tt.expected.readFileError != nil {
					assert.True(t, errors.Len() > 0, "failed while expected errors")
					return
				}

				assert.True(t, errors.Len() == 0, "failed while expected no errors")
				assert.True(t, result.Len() > 0, "failed while expected result")
			}()

			mockUsecase.EXPECT().ReadFile(mock.Anything, tt.args.path).Return(tt.expected.file, tt.expected.readFileError)
			if tt.expected.readFileError != nil {
				mockUsecase.EXPECT().ExtractUserError(tt.expected.readFileError).Return(tt.expected.readFileError)
				return
			}

			mockUsecase.EXPECT().AddFile(mock.Anything, tt.args.name, tt.expected.file, tt.args.lockPassword).Return(tt.expected.usecaseError)
			if tt.expected.usecaseError != nil {
				mockUsecase.EXPECT().ExtractUserError(tt.expected.usecaseError).Return(tt.expected.usecaseError)
				return
			}
		})
	}
}
