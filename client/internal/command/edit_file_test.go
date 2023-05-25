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

func TestEditFileCmd(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while init config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while init logger")

	type testArgs struct {
		input        []string
		name         string
		newName      string
		lockPassword string
	}

	type testExpected struct {
		file          []byte
		filePath      string
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
				input:        []string{"some-name", "-p some/path", "-n new-some"},
				name:         "some-name",
				newName:      "new-some",
				lockPassword: "some-password",
			},
			expected: testExpected{
				file:     []byte("some-file"),
				filePath: "some/path",
			},
		},
		{
			name: "read_file_error",
			args: testArgs{
				input:        []string{"some-name", "-p some/path", "-n new-some"},
				name:         "some-name",
				newName:      "new-some",
				lockPassword: "some-password",
			},
			expected: testExpected{
				file:          []byte("some-file"),
				filePath:      "some/path",
				readFileError: errors.New("some-error"),
			},
		},
		{
			name: "usecase_error",
			args: testArgs{
				input:        []string{"some-name", "-p some/path", "-n new-some"},
				name:         "some-name",
				newName:      "new-some",
				lockPassword: "some-password",
			},
			expected: testExpected{
				file:         []byte("some-file"),
				filePath:     "some/path",
				usecaseError: errors.New("some-error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {

			mockUsecase := NewMockEditFileUsecase(t)

			defer func() {
				result := new(bytes.Buffer)
				errors := new(bytes.Buffer)
				in := new(bytes.Buffer)
				in.WriteString(tt.args.lockPassword + "\n")

				cmd := NewEditFileCmd(mockUsecase, cfg, lg)
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

			if tt.expected.filePath != "" {
				mockUsecase.EXPECT().ReadFile(mock.Anything, tt.expected.filePath).Return(tt.expected.file, tt.expected.readFileError)
				if tt.expected.readFileError != nil {
					mockUsecase.EXPECT().ExtractUserError(tt.expected.readFileError).Return(tt.expected.readFileError)
					return
				}
			}

			mockUsecase.EXPECT().EditFile(mock.Anything, tt.args.name, tt.args.newName, tt.expected.file, tt.args.lockPassword).Return(tt.expected.usecaseError)
			if tt.expected.usecaseError != nil {
				mockUsecase.EXPECT().ExtractUserError(tt.expected.usecaseError).Return(tt.expected.usecaseError)
				return
			}
		})
	}
}
